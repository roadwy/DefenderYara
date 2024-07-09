
rule Trojan_Win32_DanaBot_BA_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 31 b8 [0-20] 83 f0 ?? 83 ad [0-30] 39 bd [0-30] 90 13 [0-20] 8b 8d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}