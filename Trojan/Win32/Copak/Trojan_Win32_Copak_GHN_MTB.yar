
rule Trojan_Win32_Copak_GHN_MTB{
	meta:
		description = "Trojan:Win32/Copak.GHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 31 bf 7f 98 84 7f 42 81 c1 90 01 04 39 d9 75 e9 09 fa 01 c2 c3 81 ef 90 01 04 96 0d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}