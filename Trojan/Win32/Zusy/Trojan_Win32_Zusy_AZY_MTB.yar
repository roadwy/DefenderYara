
rule Trojan_Win32_Zusy_AZY_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c2 47 c1 e8 18 0f b6 0c 85 f0 bc 5e 00 0f b6 46 ff 8b 0c 8d f0 b0 5e 00 0f b6 04 85 f0 bc 5e 00 33 0c 85 f0 a8 5e 00 0f b6 c2 8b 56 02 0f b6 04 85 f0 bc 5e 00 33 0c 85 f0 a4 5e 00 0f b6 06 0f b6 04 85 f0 bc 5e 00 33 0c 85 f0 ac 5e 00 8b c2 c1 e8 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}