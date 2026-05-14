
rule Trojan_Win32_Androm_BAO_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {ba 00 10 00 00 b8 80 ae 3b 00 03 45 ?? 2b c2 83 c0 04 89 45 ?? ff 75 ?? b9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}