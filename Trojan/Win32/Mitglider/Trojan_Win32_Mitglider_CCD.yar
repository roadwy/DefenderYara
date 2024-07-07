
rule Trojan_Win32_Mitglider_CCD{
	meta:
		description = "Trojan:Win32/Mitglider.CCD,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 7d 08 f7 d0 eb 0b 47 80 77 ff 05 d0 47 ff f6 57 ff 3b 7d 0c 75 f0 c9 c2 08 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}