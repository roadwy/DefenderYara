
rule Trojan_Win32_LummaStealer_GZX_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 d1 c1 e9 06 80 c1 c0 88 4d 00 80 e2 3f 80 ca 80 88 55 01 } //5
		$a_01_1 = {83 cb 0a 0f af 5c 24 0c 83 74 24 0c 0a 8b 7c 24 04 83 e7 f5 0f af 7c 24 0c 89 7c 24 04 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}