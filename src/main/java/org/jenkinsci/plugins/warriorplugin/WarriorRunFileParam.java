package org.jenkinsci.plugins.warriorplugin;

import java.io.Serializable;
import org.kohsuke.stapler.DataBoundConstructor;
import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import org.kohsuke.stapler.export.Exported;
import org.kohsuke.stapler.export.ExportedBean;

@ExportedBean
public class WarriorRunFileParam extends AbstractDescribableImpl<WarriorRunFileParam> implements Serializable{
    private static final long serialVersionUID = 1L;
    public final String runFile;

     @DataBoundConstructor
     public WarriorRunFileParam(String runFile){
         this.runFile=runFile;
     }

     @Exported
     public String getRunFile(){
        return runFile;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<WarriorRunFileParam> {

        @Override
        public String getDisplayName() {
            return "";
        }
    }
}