
rule Trojan_Win32_LummaStealer_MVV_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 8b 4c 24 18 03 c6 0f b6 c0 8a 44 04 ?? 30 04 29 45 3b ac 24 28 02 00 00 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}