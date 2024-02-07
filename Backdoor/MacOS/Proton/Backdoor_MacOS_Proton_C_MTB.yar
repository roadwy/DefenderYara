
rule Backdoor_MacOS_Proton_C_MTB{
	meta:
		description = "Backdoor:MacOS/Proton.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 6e 7a 69 70 20 2d 64 20 2f 74 6d 70 20 25 40 2f 2e 70 6c 2e 7a 69 70 } //01 00  unzip -d /tmp %@/.pl.zip
		$a_00_1 = {6f 70 65 6e 20 2f 74 6d 70 2f 55 70 64 61 74 65 72 2e 61 70 70 } //01 00  open /tmp/Updater.app
		$a_00_2 = {63 6f 6d 2e 45 6c 74 69 6d 61 2e 55 70 64 61 74 65 72 41 67 65 6e 74 } //00 00  com.Eltima.UpdaterAgent
	condition:
		any of ($a_*)
 
}