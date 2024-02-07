
rule TrojanSpy_Win32_Goldun_CB{
	meta:
		description = "TrojanSpy:Win32/Goldun.CB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 6c 73 65 20 69 66 20 28 64 6f 63 75 6d 65 6e 74 2e 74 65 63 6c 61 64 6f 2e 70 61 73 73 77 6f 72 64 2e 76 61 6c 75 65 2e 6c 65 6e 67 74 68 20 3d 3d 20 30 29 } //01 00  else if (document.teclado.password.value.length == 0)
		$a_01_1 = {62 61 6e 6b 69 6e 67 2e 73 70 61 72 6b 61 73 73 65 2d } //01 00  banking.sparkasse-
		$a_01_2 = {3f 57 47 23 62 6f 6a 64 6d 3e 21 6f 66 65 77 21 23 60 6c 6f 70 73 62 6d 3e 21 34 21 23 75 62 6f 6a 64 6d 3e 21 61 6c 77 77 6c 6e 21 3d 3f 4a 4d 53 56 57 23 77 7a 73 66 3e 21 77 66 7b 77 21 23 6d 62 6e 66 3e 21 6f 6c 64 6a 6d 21 23 23 6c 6d 45 6c 60 76 70 3e 21 69 62 75 62 70 60 71 6a 73 77 39 64 76 62 71 67 62 71 45 6c 60 6c 2b 24 6f 6c 64 6a 6d 24 2a 38 21 23 6e 62 7b 6f 66 6d 64 77 6b 3e 21 31 33 21 23 77 62 61 6a 6d 67 66 7b 3e 21 32 21 23 60 6f 62 70 70 3e 21 57 66 7b 77 6c 40 6c 6d 77 66 6d 6a 67 6c 21 3d 3f 2c 57 47 3d } //01 00  ?WG#bojdm>!ofew!#`lopsbm>!4!#ubojdm>!alwwln!=?JMSVW#wzsf>!wf{w!#mbnf>!oldjm!##lmEl`vp>!ibubp`qjsw9dvbqgbqEl`l+$oldjm$*8!#nb{ofmdwk>!13!#wbajmgf{>!2!#`obpp>!Wf{wl@lmwfmjgl!=?,WG=
		$a_01_3 = {65 72 77 65 69 73 75 6e 67 2e 63 67 69 00 00 00 00 67 6f 6c 64 2e 63 6f 6d 2f 61 63 63 74 2f 6c 69 2e 00 } //01 00 
		$a_01_4 = {63 65 6d 00 65 62 61 6e 6b 69 6e 74 65 72 00 00 63 6c 69 65 6e 74 5f 00 63 70 73 69 6e 74 65 72 6e 65 74 62 61 6e 6b 69 } //00 00 
	condition:
		any of ($a_*)
 
}