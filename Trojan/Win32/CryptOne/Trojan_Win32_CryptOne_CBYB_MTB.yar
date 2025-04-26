
rule Trojan_Win32_CryptOne_CBYB_MTB{
	meta:
		description = "Trojan:Win32/CryptOne.CBYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 a4 8b 45 ec 8b 55 d8 01 02 8b 45 a8 03 45 9c 03 45 ec 03 45 a4 89 45 ac 8b 45 ac 8b 55 d8 31 02 83 45 ec ?? 83 45 d8 ?? 8b 45 ec 3b 05 d4 dd 5b 00 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}