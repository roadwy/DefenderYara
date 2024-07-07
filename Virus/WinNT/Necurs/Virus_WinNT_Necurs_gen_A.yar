
rule Virus_WinNT_Necurs_gen_A{
	meta:
		description = "Virus:WinNT/Necurs.gen!A.dummy,SIGNATURE_TYPE_ARHSTR_EXT,0f 00 0d 00 0d 00 00 "
		
	strings :
		$a_00_0 = {4e 65 63 75 72 73 20 64 75 6d 6d 79 20 64 65 74 65 63 74 69 6f 6e } //1 Necurs dummy detection
		$a_00_1 = {49 6e 74 65 72 6e 61 6c 20 74 65 73 74 20 6f 6e 6c 79 2e 20 44 6f 20 6e 6f 74 20 64 69 73 74 72 69 62 75 74 65 20 6f 75 74 73 69 64 65 20 79 6f 75 72 20 74 65 61 6d 21 } //1 Internal test only. Do not distribute outside your team!
		$a_00_2 = {68 41 67 43 41 41 43 4a 42 6d 61 42 66 67 53 7a 31 77 2b 46 77 77 41 41 41 47 54 67 52 71 41 50 38 32 36 49 50 6d } //1 hAgCAACJBmaBfgSz1w+FwwAAAGTgRqAP826IPm
		$a_00_3 = {47 24 4d 66 5a 4d 53 72 4e 6b 48 4b 41 4d 4b 65 2d 2b 54 47 46 32 33 70 45 56 32 36 63 71 50 54 34 58 61 } //1 G$MfZMSrNkHKAMKe-+TGF23pEV26cqPT4Xa
		$a_00_4 = {71 58 63 43 66 44 72 32 28 32 58 66 69 4d 72 6d 61 6c 24 44 2d 2d 28 4b 71 48 51 42 40 24 55 49 71 60 26 5b 64 4a 23 39 } //1 qXcCfDr2(2XfiMrmal$D--(KqHQB@$UIq`&[dJ#9
		$a_00_5 = {4a 65 40 66 70 28 4b 71 6c 6c 5b 24 56 6b 40 49 50 58 61 4e 48 65 23 6b 32 23 48 56 6b 59 4b 5a } //1 Je@fp(Kqll[$Vk@IPXaNHe#k2#HVkYKZ
		$a_00_6 = {53 49 50 46 65 29 49 39 21 36 6b 25 2c 42 27 35 6c 72 25 61 31 48 5b 71 6a 6d 28 2a 4b } //1 SIPFe)I9!6k%,B'5lr%a1H[qjm(*K
		$a_00_7 = {64 26 58 6b 66 48 33 6c 36 4a 72 50 56 6a 5b 24 59 5a 2a 42 71 28 70 50 63 50 52 2d 62 6c 51 5a 62 } //1 d&XkfH3l6JrPVj[$YZ*Bq(pPcPR-blQZb
		$a_00_8 = {48 56 4e 4f 41 26 40 52 31 21 63 50 21 43 36 53 2d 38 34 64 49 4b 6b 2b 26 69 33 71 34 4a 4b 71 44 64 29 23 34 55 41 47 34 } //1 HVNOA&@R1!cP!C6S-84dIKk+&i3q4JKqDd)#4UAG4
		$a_00_9 = {2d 4d 5a 45 4c 43 72 30 30 6b 26 32 4e 4a 2a 6a 6b 38 21 2c 40 42 27 48 40 60 6b 6d 23 5a 31 60 2b 6b 69 23 5b 55 2d 23 59 } //1 -MZELCr00k&2NJ*jk8!,@B'H@`km#Z1`+ki#[U-#Y
		$a_00_10 = {39 4d 48 72 4b 36 6d 5a 45 62 55 42 44 26 58 40 65 2a 7a 50 26 5b 41 34 51 4d 61 40 43 40 26 70 } //1 9MHrK6mZEbUBD&X@e*zP&[A4QMa@C@&p
		$a_00_11 = {49 6d 59 71 6a 52 72 52 6d 52 69 72 6d 5b 6d 49 33 72 5a 61 32 63 49 6a 49 65 42 52 6a 49 62 48 24 49 31 61 49 63 49 69 69 5a } //1 ImYqjRrRmRirm[mI3rZa2cIjIeBRjIbH$I1aIcIiiZ
		$a_00_12 = {4d 6a 4e 73 52 63 70 54 30 4e 44 24 66 63 61 62 47 21 38 28 4d 29 29 35 47 70 44 49 47 4b 50 56 5a } //1 MjNsRcpT0ND$fcabG!8(M))5GpDIGKPVZ
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=13
 
}