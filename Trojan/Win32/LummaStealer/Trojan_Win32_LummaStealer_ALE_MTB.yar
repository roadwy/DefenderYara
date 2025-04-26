
rule Trojan_Win32_LummaStealer_ALE_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ALE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c7 83 e7 0d 89 c3 83 e3 02 89 de 83 f6 02 0f af f7 83 cf 02 0f af fb 89 c5 81 cd 50 65 c5 1d 89 cb 81 cb af 9a 3a e2 21 eb f7 d3 01 f3 01 fb 89 de 21 d6 01 d3 01 f6 29 f3 80 c3 95 88 5c 04 0c 40 49 83 f8 1b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}