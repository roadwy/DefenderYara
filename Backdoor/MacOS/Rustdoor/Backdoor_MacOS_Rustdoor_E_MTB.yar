
rule Backdoor_MacOS_Rustdoor_E_MTB{
	meta:
		description = "Backdoor:MacOS/Rustdoor.E!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 63 5f 72 65 6d 6f 74 65 5f 6c 6f 61 64 5f 63 6f 6d 6d 61 6e 64 } //1 rc_remote_load_command
		$a_01_1 = {6c 61 75 6e 63 68 5f 69 6e 6a 65 63 74 } //1 launch_inject
		$a_01_2 = {63 6f 6d 6d 61 6e 64 74 61 73 6b 6b 69 6c 6c 64 6f 77 6e 6c 6f 61 64 } //1 commandtaskkilldownload
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}