
rule TrojanSpy_Win32_Banker_AMB{
	meta:
		description = "TrojanSpy:Win32/Banker.AMB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 1b 8a 4c 0b ff 0f b7 5d f0 c1 eb 08 32 cb 88 4c 10 ff 0f b7 45 f2 8b 55 fc 0f b6 44 02 ff 66 03 45 f0 66 69 c0 6d ce 66 05 bf 58 } //2
		$a_01_1 = {28 00 49 00 44 00 5f 00 50 00 43 00 2c 00 20 00 55 00 53 00 42 00 4c 00 4f 00 47 00 29 00 20 00 56 00 61 00 6c 00 75 00 65 00 73 00 20 00 28 00 3a 00 49 00 44 00 5f 00 50 00 43 00 2c 00 20 00 3a 00 55 00 53 00 42 00 4c 00 4f 00 47 00 29 00 } //1 (ID_PC, USBLOG) Values (:ID_PC, :USBLOG)
		$a_01_2 = {52 00 45 00 2d 00 43 00 4f 00 50 00 49 00 41 00 44 00 4f 00 20 00 50 00 41 00 52 00 41 00 } //1 RE-COPIADO PARA
		$a_01_3 = {43 00 68 00 72 00 6f 00 6d 00 65 00 5f 00 57 00 69 00 64 00 67 00 65 00 74 00 57 00 69 00 6e 00 5f 00 } //1 Chrome_WidgetWin_
		$a_01_4 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 55 00 49 00 57 00 69 00 6e 00 64 00 6f 00 77 00 43 00 6c 00 61 00 73 00 73 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}