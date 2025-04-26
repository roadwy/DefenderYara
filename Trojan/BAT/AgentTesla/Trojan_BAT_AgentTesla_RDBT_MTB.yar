
rule Trojan_BAT_AgentTesla_RDBT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 63 33 38 66 35 65 33 2d 33 61 35 31 2d 34 33 63 35 2d 38 39 37 61 2d 31 37 38 32 32 38 64 37 66 34 32 30 } //1 bc38f5e3-3a51-43c5-897a-178228d7f420
		$a_01_1 = {55 70 64 61 74 65 20 66 72 6f 6d 20 4a 61 76 61 } //1 Update from Java
		$a_01_2 = {4e 6f 72 74 68 41 6d 65 72 69 63 61 55 70 64 61 74 65 2e 65 78 65 } //1 NorthAmericaUpdate.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}