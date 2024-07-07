
rule Trojan_Win32_Neysd_A{
	meta:
		description = "Trojan:Win32/Neysd.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {25 73 3f 61 61 61 61 3d 33 33 33 33 26 66 66 66 66 3d 25 73 } //1 %s?aaaa=3333&ffff=%s
		$a_01_1 = {25 73 3a 52 55 4e 5f 52 45 42 4f 4f 54 } //1 %s:RUN_REBOOT
		$a_01_2 = {50 61 73 73 77 6f 72 64 20 45 78 70 69 72 69 65 64 20 54 69 6d 65 3a } //1 Password Expiried Time:
		$a_01_3 = {63 65 72 74 32 30 31 33 2e 64 61 74 } //1 cert2013.dat
		$a_00_4 = {53 44 5f 32 30 31 33 20 49 73 20 52 75 6e 6e 69 6e 67 21 } //1 SD_2013 Is Running!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}