
rule TrojanSpy_Win32_Goldun_BX{
	meta:
		description = "TrojanSpy:Win32/Goldun.BX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_01_0 = {5c 72 65 64 69 72 65 63 74 5f 66 61 6b 65 2e 74 78 74 00 00 ff ff ff ff 15 00 00 00 72 65 64 69 72 65 63 } //1
		$a_02_1 = {65 2d 67 6f 6c 64 2e 63 6f 6d 00 00 90 02 0a 2f 61 63 63 74 2f 6c 69 2e 61 73 90 00 } //1
		$a_01_2 = {ff ff ff 0b 00 00 00 63 69 74 69 62 61 6e 6b 2e 64 65 00 ff ff ff ff 0a 00 00 00 31 32 33 34 35 } //1
		$a_01_3 = {26 74 65 78 74 3d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 20 5b 48 4f 4c 44 45 52 5f 4d 41 49 4c 5f 45 2d 47 4f 4c 44 5d } //1 &text=------------------------------------ [HOLDER_MAIL_E-GOLD]
		$a_01_4 = {5b 49 50 3d 2f 2f 2a 7e 7e 7e 7e 7e 2a 2f 2f 2f 2f 2a 44 41 54 45 54 49 4d 45 2a 2f 2f 5d } //1 [IP=//*~~~~~*////*DATETIME*//]
		$a_01_5 = {2a 2a 2a 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 20 5b 55 52 4c 3d } //1 ***------------------------------------ [URL=
		$a_01_6 = {72 65 64 69 72 65 63 74 5f 66 61 6b 65 2e 74 78 74 } //1 redirect_fake.txt
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=4
 
}