
rule Trojan_Win32_Sabsik_MNB_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.MNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 00 66 85 e1 83 e0 0f 33 c2 f7 c1 c2 4b 87 0b 81 ff 54 6c 2e 2a 81 e6 ff 00 00 00 f8 66 85 ea 33 c6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}