
rule Trojan_Win32_AveMariaRat_MT_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRat.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 51 ff 15 ?? ?? ?? ?? 89 c3 6a 00 50 ff 15 90 0a 30 00 c6 84 10 ?? ?? ?? ?? ?? 42 75 ?? 6a 00 68 80 00 00 00 6a 03 6a 00 6a 07 68 00 00 00 80 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}