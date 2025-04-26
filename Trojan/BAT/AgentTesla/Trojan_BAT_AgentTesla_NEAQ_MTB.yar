
rule Trojan_BAT_AgentTesla_NEAQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 66 36 63 33 35 36 34 2d 31 37 39 35 2d 34 35 38 34 2d 38 61 34 38 2d 62 37 32 30 63 62 33 30 65 61 38 61 } //5 3f6c3564-1795-4584-8a48-b720cb30ea8a
		$a_01_1 = {48 47 67 47 47 67 37 2e 65 78 65 } //2 HGgGGg7.exe
		$a_01_2 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 36 } //1 Confuser.Core 1.6
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=8
 
}