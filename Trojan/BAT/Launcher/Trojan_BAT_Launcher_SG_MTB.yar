
rule Trojan_BAT_Launcher_SG_MTB{
	meta:
		description = "Trojan:BAT/Launcher.SG!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 20 72 6f 62 6c 6f 78 70 72 6f 63 65 73 73 2e 62 61 74 } //1 start robloxprocess.bat
		$a_01_1 = {68 00 69 00 64 00 65 00 69 00 74 00 2e 00 62 00 61 00 74 00 } //1 hideit.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}