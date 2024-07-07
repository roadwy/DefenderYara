
rule Trojan_BAT_AgentTesla_ASFV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {e4 02 f0 02 f4 02 0c 03 f8 02 e4 02 02 03 f3 02 12 03 e6 02 ef 02 f4 02 af 06 17 03 f1 02 0c 03 f0 02 12 03 f7 02 15 03 e0 02 eb 02 f3 02 0c 03 f4 02 ed 02 ef 02 0a 03 0a 03 12 03 f7 02 d0 02 cf 02 e7 02 f2 02 18 03 e0 02 ce 02 ec 02 e4 02 06 03 f4 02 f7 02 d1 02 af 06 af 06 ef 02 ce 02 16 03 e3 02 f2 02 d0 02 ef 02 d3 02 f2 02 cf 02 f8 02 } //2
		$a_01_1 = {ea 02 00 03 f6 02 02 03 e5 02 f5 02 f6 02 0a 03 d3 02 ff 02 ce 02 cf 02 ef 02 f7 02 09 03 f0 02 e9 02 01 03 18 03 f3 02 d3 02 f8 02 05 03 e0 02 e8 02 02 03 f5 02 01 03 18 03 eb 02 f5 02 0a 03 f8 02 ec 02 09 03 d7 02 e3 02 f2 02 e5 02 cf 02 f4 02 f0 02 08 03 f0 02 ec 02 ef 02 0c 03 f7 02 d0 02 af 06 e6 02 0a 03 e3 02 ef 02 f3 02 02 03 e9 02 00 03 f4 02 0a 03 13 03 ef 02 f3 02 f4 02 0a 03 00 03 d1 02 e0 02 f7 02 00 03 f5 02 06 03 16 03 f0 02 09 03 11 03 af 06 03 03 0c 03 0a 03 17 03 f0 02 e5 02 16 03 0f 03 f5 02 f4 02 0e 03 d3 02 02 03 } //2
		$a_01_2 = {45 55 34 5f 4d 6f 64 5f 4d 61 6e 61 67 65 72 2e 52 65 73 6f 75 72 63 65 73 } //1 EU4_Mod_Manager.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}