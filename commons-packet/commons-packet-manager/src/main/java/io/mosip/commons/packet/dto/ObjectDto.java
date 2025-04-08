package io.mosip.commons.packet.dto;

import java.io.Serializable;
import java.util.Date;

public class ObjectDto implements Serializable {
    private String source;
    private String process;
    private String objectName;
    private Date lastModified;

    public String getSource() {
        return this.source;
    }

    public String getProcess() {
        return this.process;
    }

    public String getObjectName() {
        return this.objectName;
    }

    public Date getLastModified() {
        return this.lastModified;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public void setProcess(String process) {
        this.process = process;
    }

    public void setObjectName(String objectName) {
        this.objectName = objectName;
    }

    public void setLastModified(Date lastModified) {
        this.lastModified = lastModified;
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        } else if (!(o instanceof ObjectDto)) {
            return false;
        } else {
            ObjectDto other = (ObjectDto)o;
            if (!other.canEqual(this)) {
                return false;
            } else {
                label59: {
                    Object this$source = this.getSource();
                    Object other$source = other.getSource();
                    if (this$source == null) {
                        if (other$source == null) {
                            break label59;
                        }
                    } else if (this$source.equals(other$source)) {
                        break label59;
                    }

                    return false;
                }

                Object this$process = this.getProcess();
                Object other$process = other.getProcess();
                if (this$process == null) {
                    if (other$process != null) {
                        return false;
                    }
                } else if (!this$process.equals(other$process)) {
                    return false;
                }

                Object this$objectName = this.getObjectName();
                Object other$objectName = other.getObjectName();
                if (this$objectName == null) {
                    if (other$objectName != null) {
                        return false;
                    }
                } else if (!this$objectName.equals(other$objectName)) {
                    return false;
                }

                Object this$lastModified = this.getLastModified();
                Object other$lastModified = other.getLastModified();
                if (this$lastModified == null) {
                    if (other$lastModified != null) {
                        return false;
                    }
                } else if (!this$lastModified.equals(other$lastModified)) {
                    return false;
                }

                return true;
            }
        }
    }

    protected boolean canEqual(Object other) {
        return other instanceof ObjectDto;
    }

    public int hashCode() {
        boolean PRIME = true;
        int result = 1;
        Object $source = this.getSource();
        result = result * 59 + ($source == null ? 43 : $source.hashCode());
        Object $process = this.getProcess();
        result = result * 59 + ($process == null ? 43 : $process.hashCode());
        Object $objectName = this.getObjectName();
        result = result * 59 + ($objectName == null ? 43 : $objectName.hashCode());
        Object $lastModified = this.getLastModified();
        result = result * 59 + ($lastModified == null ? 43 : $lastModified.hashCode());
        return result;
    }

    public String toString() {
        String var10000 = this.getSource();
        return "ObjectDto(source=" + var10000 + ", process=" + this.getProcess() + ", objectName=" + this.getObjectName() + ", lastModified=" + this.getLastModified() + ")";
    }

    public ObjectDto(String source, String process, String objectName, Date lastModified) {
        this.source = source;
        this.process = process;
        this.objectName = objectName;
        this.lastModified = lastModified;
    }

    public ObjectDto() {
    }
}
