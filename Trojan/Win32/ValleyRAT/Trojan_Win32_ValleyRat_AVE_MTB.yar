
rule Trojan_Win32_ValleyRat_AVE_MTB{
	meta:
		description = "Trojan:Win32/ValleyRat.AVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 83 ec 1c 8b 45 08 8b 58 04 8b 30 c7 44 24 0c ?? ?? ?? ?? c7 44 24 08 ?? ?? ?? ?? 8b 03 c7 04 24 ?? ?? ?? ?? 89 44 24 04 ff 15 ?? ?? ?? ?? 8b 0b 89 c7 83 ec 10 f3 a4 ff d0 8d 65 f4 31 c0 5b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}