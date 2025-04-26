
rule Trojan_BAT_Nanocore_ABDR_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 06 08 06 8e 69 5d 91 7e ?? ?? ?? 04 08 91 61 d2 6f ?? ?? ?? 0a 08 17 58 0c 08 7e ?? ?? ?? 04 8e 69 32 dc 07 6f ?? ?? ?? 0a 2a } //4
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}