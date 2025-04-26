
rule Trojan_Win32_LummaStealer_TRI_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.TRI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 c2 05 3a ac 7c c9 31 c2 21 ca 31 c2 89 54 24 0c 8b 44 24 0c 04 6a 8b 4c 24 04 88 44 0c 38 ff 44 24 04 8b 44 24 04 83 f8 2d 72 c2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}