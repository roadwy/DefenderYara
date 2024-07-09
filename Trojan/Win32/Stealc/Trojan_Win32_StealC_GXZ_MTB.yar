
rule Trojan_Win32_StealC_GXZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 14 1e 83 ff 0f ?? ?? 6a 00 6a 00 6a 00 e8 05 45 ff ff 46 3b f7 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}