
rule Trojan_Win32_Small_GL{
	meta:
		description = "Trojan:Win32/Small.GL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 7e } //1 %USERPROFILE%\Application Data\~
		$a_01_1 = {3e 48 62 68 6f 7e 76 49 74 74 6f 3e 47 48 62 68 6f 7e 76 28 29 47 49 6e 75 7f 77 77 28 29 35 7e 63 7e } //1 䠾桢繯䥶瑴㹯䡇桢繯⡶䜩湉罵睷⤨縵繣
		$a_01_2 = {33 36 30 73 64 3b 33 36 30 72 70 3b 33 36 30 64 65 65 70 73 63 61 6e 3b 44 53 4d 61 69 6e 3b 6b 72 6e 6c 33 36 30 73 76 63 3b 65 67 75 69 3b 65 6b 72 6e 3b 6b 69 73 73 76 63 3b 6b 73 77 65 62 73 68 69 65 6c 64 3b 5a 68 75 44 6f 6e 67 46 61 6e 67 59 75 3b } //1 360sd;360rp;360deepscan;DSMain;krnl360svc;egui;ekrn;kissvc;kswebshield;ZhuDongFangYu;
		$a_01_3 = {2e 74 78 74 00 00 00 00 ff ff ff ff 08 00 00 00 4f 48 48 62 68 50 72 6f 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}