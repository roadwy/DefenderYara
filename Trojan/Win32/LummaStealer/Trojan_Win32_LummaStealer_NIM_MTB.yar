
rule Trojan_Win32_LummaStealer_NIM_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 44 24 0c 30 04 2f 83 fb 0f 75 0b 8b 4c 24 10 51 ff ?? ?? ?? ?? ?? 47 3b fb 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}