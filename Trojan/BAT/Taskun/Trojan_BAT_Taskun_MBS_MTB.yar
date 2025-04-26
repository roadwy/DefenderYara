
rule Trojan_BAT_Taskun_MBS_MTB{
	meta:
		description = "Trojan:BAT/Taskun.MBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 08 91 1f 7f 30 07 72 f3 08 00 70 2b 05 72 fd 08 00 70 0d 04 07 08 91 } //2
		$a_01_1 = {53 75 70 65 72 41 64 76 65 6e 74 75 72 65 2e 50 72 } //1 SuperAdventure.Pr
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}