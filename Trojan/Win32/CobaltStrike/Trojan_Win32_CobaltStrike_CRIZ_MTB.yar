
rule Trojan_Win32_CobaltStrike_CRIZ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CRIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 89 c1 8d 50 01 83 e1 ?? 8a 0c 0f 8b 7d 14 32 0c 07 88 0c 03 89 d0 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}