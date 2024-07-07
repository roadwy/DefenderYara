
rule Trojan_Win32_Emotet_PDW_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 45 0f b6 94 14 90 01 04 30 55 90 00 } //1
		$a_81_1 = {6a 4c 39 67 6d 66 53 6d 6e 64 57 6a 38 77 6d 73 49 4c 70 6f 6c 5a 48 62 53 47 30 4d 4a 6f 7a 6e 36 51 52 72 66 47 5a } //1 jL9gmfSmndWj8wmsILpolZHbSG0MJozn6QRrfGZ
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}