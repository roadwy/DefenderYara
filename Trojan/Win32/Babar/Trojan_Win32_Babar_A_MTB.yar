
rule Trojan_Win32_Babar_A_MTB{
	meta:
		description = "Trojan:Win32/Babar.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d b3 32 a5 35 5c af 0a af eb 1a ce 3d ca 22 bf 2f 4a b9 71 eb 71 e1 80 73 d8 21 b8 2e 49 b8 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}