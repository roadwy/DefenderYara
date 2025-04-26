
rule Trojan_Win32_AsyncRat_ASA_MTB{
	meta:
		description = "Trojan:Win32/AsyncRat.ASA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 57 83 c4 04 81 f3 10 0e 01 00 81 f3 0d 27 00 00 81 eb 58 52 00 00 5b 56 81 ce ea 17 00 00 5e 52 52 83 c4 04 81 ea e0 4e 01 00 81 ca 45 db 00 00 5a 51 81 c9 f8 99 00 00 81 e9 e4 5e 00 00 59 52 83 ec 14 e8 ?? ?? ?? ?? 00 37 32 50 43 45 46 3a 48 37 32 83 c4 18 81 c2 fc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}