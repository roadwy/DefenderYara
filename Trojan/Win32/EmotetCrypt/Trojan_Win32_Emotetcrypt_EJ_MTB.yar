
rule Trojan_Win32_Emotetcrypt_EJ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.EJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 11 03 c2 33 d2 f7 35 90 01 04 89 55 f8 8b 45 08 03 45 ec 33 c9 8a 08 8b 55 fc 03 55 f8 33 c0 8a 02 03 45 1c 33 c8 8b 55 18 03 55 ec 88 0a e9 90 00 } //1
		$a_81_1 = {71 39 4c 40 43 70 71 66 6a 26 78 4e 67 68 4d 6b 37 69 4d 40 5a 29 78 72 4d 49 3c 45 4f 29 65 21 71 35 5a 49 57 45 45 6c 78 54 51 33 50 79 46 5e 37 42 68 43 6f 79 57 38 28 70 6a 69 25 66 3f 64 5f 66 61 3c 72 40 42 49 47 66 4b 37 64 77 3f 2b 6c 40 29 33 25 41 75 50 29 35 47 51 64 6e 40 3f 31 54 3e 74 5e 6c 58 5e 43 35 6c 34 39 66 68 47 64 49 47 37 2b } //1 q9L@Cpqfj&xNghMk7iM@Z)xrMI<EO)e!q5ZIWEElxTQ3PyF^7BhCoyW8(pji%f?d_fa<r@BIGfK7dw?+l@)3%AuP)5GQdn@?1T>t^lX^C5l49fhGdIG7+
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}