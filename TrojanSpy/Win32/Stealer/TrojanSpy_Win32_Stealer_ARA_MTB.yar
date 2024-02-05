
rule TrojanSpy_Win32_Stealer_ARA_MTB{
	meta:
		description = "TrojanSpy:Win32/Stealer.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0f 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 46 69 6c 65 57 } //01 00 
		$a_80_2 = {57 69 6e 64 44 62 67 } //WindDbg  01 00 
		$a_80_3 = {6f 6c 6c 79 44 62 67 } //ollyDbg  01 00 
		$a_80_4 = {78 36 34 64 62 67 } //x64dbg  01 00 
		$a_80_5 = {78 33 32 64 62 67 } //x32dbg  01 00 
		$a_80_6 = {4f 62 73 69 64 69 61 6e 47 55 49 } //ObsidianGUI  01 00 
		$a_80_7 = {49 6d 6d 44 62 67 } //ImmDbg  01 00 
		$a_80_8 = {5a 65 74 61 20 44 65 62 75 67 67 65 72 } //Zeta Debugger  01 00 
		$a_80_9 = {52 6f 63 6b 20 44 65 62 75 67 67 65 72 } //Rock Debugger  01 00 
		$a_80_10 = {50 52 4f 47 52 41 4d 46 49 4c 45 53 } //PROGRAMFILES  01 00 
		$a_80_11 = {5c 56 4d 57 61 72 65 5c } //\VMWare\  01 00 
		$a_80_12 = {5c 6f 72 61 63 6c 65 5c 76 69 72 74 75 61 6c 62 6f 78 20 67 75 65 73 74 20 61 64 64 69 74 69 6f 6e 73 5c } //\oracle\virtualbox guest additions\  02 00 
		$a_80_13 = {4d 3b 69 3b 63 3b 72 3b 6f 3b 73 3b 6f 3b 66 3b 74 3b 20 3b 45 3b 6e 3b 68 3b 61 3b 6e 3b 63 3b 65 3b 64 3b 20 3b 52 3b 53 3b 41 3b 20 3b 61 3b 6e 3b 64 3b 20 3b 41 3b 45 3b 53 3b 20 3b 43 3b 72 3b 79 3b 70 3b 74 3b 6f 3b 67 3b 72 3b 61 3b 70 3b 68 3b 69 3b 63 3b 20 3b 50 3b 72 3b 6f 3b 76 3b 69 3b 64 3b 65 3b 72 3b } //M;i;c;r;o;s;o;f;t; ;E;n;h;a;n;c;e;d; ;R;S;A; ;a;n;d; ;A;E;S; ;C;r;y;p;t;o;g;r;a;p;h;i;c; ;P;r;o;v;i;d;e;r;  02 00 
		$a_80_14 = {41 6d 75 72 6e 63 61 77 65 6e 63 78 72 64 79 } //Amurncawencxrdy  00 00 
	condition:
		any of ($a_*)
 
}