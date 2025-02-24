
rule Trojan_Win32_LummaStealer_PE_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 85 ff 74 11 8b c8 83 e1 03 8a 4c 0d 10 30 0c 06 40 3b c7 72 ef ff 45 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}