
rule Trojan_Win32_Racealer_RW_MTB{
	meta:
		description = "Trojan:Win32/Racealer.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 ec 04 08 00 00 a1 90 01 04 33 c5 89 45 90 01 01 56 57 33 f6 33 ff 39 75 90 01 01 7e 90 01 01 e8 90 01 04 30 04 3b 83 7d 90 01 01 19 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}