
rule TrojanDownloader_Win32_Zlob_gen_AY{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AY,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0d 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 49 6e 70 72 6f 63 53 65 72 76 65 72 33 32 } //1 \InprocServer32
		$a_00_1 = {7b 37 43 31 30 39 38 30 30 2d 41 35 44 35 2d 34 33 38 46 2d 39 36 34 30 2d 31 38 44 31 37 45 31 36 38 42 38 38 7d } //1 {7C109800-A5D5-438F-9640-18D17E168B88}
		$a_00_2 = {23 37 38 35 75 6a 74 68 67 66 72 77 33 34 36 37 36 75 74 79 6a } //1 #785ujthgfrw34676utyj
		$a_00_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_02_4 = {8d 85 f8 fd ff ff 68 ?? ?? 00 10 50 e8 ?? ?? 00 00 8d 85 f8 fd ff ff 68 ?? ?? 00 10 50 e8 ?? ?? 00 00 8d 85 f8 fd ff ff 68 ?? ?? 00 10 50 e8 ?? ?? 00 00 8d 85 f8 fd ff ff 68 ?? ?? 00 10 50 e8 ?? ?? 00 00 8d 85 f8 fd ff ff 68 ?? ?? 00 10 50 e8 ?? ?? 00 00 8d 85 f8 fd ff ff 68 ?? ?? 00 10 50 e8 ?? ?? 00 00 83 c4 30 6a 01 8d 85 f8 fd ff ff 50 ff 15 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*10+(#a_02_4  & 1)*1) >=13
 
}