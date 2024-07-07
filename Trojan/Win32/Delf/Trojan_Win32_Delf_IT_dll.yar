
rule Trojan_Win32_Delf_IT_dll{
	meta:
		description = "Trojan:Win32/Delf.IT!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3e 48 62 68 6f 7e 76 49 74 74 6f 3e 47 48 62 68 6f 7e 76 28 29 47 68 78 35 7e 63 7e } //1 >Hbho~vItto>GHbho~v()Ghx5~c~
		$a_01_1 = {3b 78 74 75 7d 72 7c 3b 4b 74 77 72 78 62 5a 7c 7e 75 6f 3b 68 6f 7a 69 6f 26 7a 6e 6f 74 } //1 ;xtu}r|;KtwrxbZ|~uo;hozio&znot
		$a_01_2 = {3b 68 6f 7a 69 6f 3b 4b 74 77 72 78 62 5a 7c 7e 75 6f } //1 ;hozio;KtwrxbZ|~uo
		$a_01_3 = {3b 33 36 30 64 65 65 70 73 63 61 6e 3b 44 53 4d 61 69 6e 3b 6b 72 6e 6c 33 36 30 73 76 63 3b 65 67 75 69 3b 65 6b 72 6e 3b 6b 69 73 73 76 63 3b 6b 73 77 65 62 73 68 69 65 6c 64 3b 5a 68 75 44 6f 6e 67 46 61 6e 67 59 75 3b 53 75 70 65 72 4b 69 6c 6c 65 72 3b } //1 ;360deepscan;DSMain;krnl360svc;egui;ekrn;kissvc;kswebshield;ZhuDongFangYu;SuperKiller;
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}