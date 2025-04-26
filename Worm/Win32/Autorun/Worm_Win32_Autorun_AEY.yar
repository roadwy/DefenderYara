
rule Worm_Win32_Autorun_AEY{
	meta:
		description = "Worm:Win32/Autorun.AEY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {4d 44 20 43 3a 5c 52 45 43 59 43 4c 45 52 5c 53 2d 31 2d 35 2d 7e 31 5c 42 44 56 5c 22 57 65 6c 63 6f 6d 65 20 61 74 20 42 44 20 56 69 72 75 73 22 } //1 MD C:\RECYCLER\S-1-5-~1\BDV\"Welcome at BD Virus"
		$a_01_1 = {66 6f 72 20 25 25 72 20 69 6e 20 28 64 3b 65 3b 66 3b 67 3b 68 3b 69 3b 6a 3b 6b 3b 6c 3b 6d 3b 6e 3b 6f 3b 70 3b 71 3b 72 3b 73 3b 74 3b 75 3b 76 29 } //1 for %%r in (d;e;f;g;h;i;j;k;l;m;n;o;p;q;r;s;t;u;v)
		$a_01_2 = {61 74 74 72 69 62 20 2b 73 20 2b 68 20 2b 72 20 2b 61 20 43 3a 5c 52 45 43 59 43 4c 45 52 5c 53 2d 31 2d 35 2d 7e 31 5c 42 44 56 5c 2a 2e 2a } //1 attrib +s +h +r +a C:\RECYCLER\S-1-5-~1\BDV\*.*
		$a_00_3 = {42 44 56 5c 61 55 74 6f 52 75 4e 2e 69 6e 46 } //1 BDV\aUtoRuN.inF
		$a_01_4 = {78 63 6f 70 79 20 42 44 56 2e 65 78 65 20 43 3a 5c 52 45 43 59 43 4c 45 52 5c 53 2d 31 2d 35 2d 7e 31 5c 42 44 56 5c 20 2f 68 20 2f 6b 20 2f 79 } //1 xcopy BDV.exe C:\RECYCLER\S-1-5-~1\BDV\ /h /k /y
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}