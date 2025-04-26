
rule Trojan_Win32_LummaStealer_PD_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 fa 89 15 [0-04] 0f bf 05 [0-04] 0f af 05 [0-04] 66 a3 [0-04] 8b 8d [0-04] 0f af 0d [0-04] 89 8d [0-04] 0f bf 15 [0-04] 03 95 [0-04] 66 89 15 [0-04] 0f bf 85 [0-04] 03 05 [0-04] 66 89 85 [0-04] 0f bf 0d [0-04] 0f af 0d [0-04] 89 0d [0-04] e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}