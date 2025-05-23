
rule Spammer_Win32_Nuwar_D{
	meta:
		description = "Spammer:Win32/Nuwar.D,SIGNATURE_TYPE_PEHSTR_EXT,18 00 14 00 15 00 00 "
		
	strings :
		$a_00_0 = {8b fe 83 c9 ff 33 c0 33 d2 f2 ae f7 d1 49 74 15 80 04 32 } //6
		$a_01_1 = {75 73 62 67 67 35 62 6d 6d } //3 usbgg5bmm
		$a_01_2 = {30 62 65 6d 70 62 65 2f 71 69 71 } //3 0bempbe/qiq
		$a_01_3 = {69 75 75 71 3b 30 30 } //3 iuuq;00
		$a_00_4 = {83 c4 38 89 c3 89 f0 25 ff 00 00 00 83 c0 1d } //4
		$a_00_5 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 27 } //4 netsh firewall set allowedprogram '
		$a_01_6 = {2f 63 6a 7b 00 75 79 } //3
		$a_01_7 = {2f 71 69 71 } //2 /qiq
		$a_01_8 = {2f 63 6a 7b } //2 /cj{
		$a_01_9 = {63 6e 74 72 2e 70 68 70 } //2 cntr.php
		$a_01_10 = {73 76 63 70 2e 63 73 76 } //2 svcp.csv
		$a_01_11 = {74 69 62 73 2e } //2 tibs.
		$a_01_12 = {70 72 6f 78 79 2e } //2 proxy.
		$a_00_13 = {89 d8 25 ff 00 00 00 83 c0 17 88 85 } //2
		$a_00_14 = {ff ff 89 da c1 ea 08 88 95 } //2
		$a_01_15 = {6e 6f 74 6f 75 74 70 6f 73 74 } //2 notoutpost
		$a_00_16 = {2e 70 68 70 3f 61 64 76 3d } //3 .php?adv=
		$a_00_17 = {3f 61 64 76 3d 25 75 } //3 ?adv=%u
		$a_00_18 = {26 63 6f 64 65 31 3d 25 63 25 63 25 63 25 63 } //3 &code1=%c%c%c%c
		$a_00_19 = {26 74 61 62 6c 65 3d 61 64 76 25 75 } //3 &table=adv%u
		$a_00_20 = {2f 61 64 6c 6f 61 64 2e 70 68 70 } //3 /adload.php
	condition:
		((#a_00_0  & 1)*6+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_00_4  & 1)*4+(#a_00_5  & 1)*4+(#a_01_6  & 1)*3+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2+(#a_01_12  & 1)*2+(#a_00_13  & 1)*2+(#a_00_14  & 1)*2+(#a_01_15  & 1)*2+(#a_00_16  & 1)*3+(#a_00_17  & 1)*3+(#a_00_18  & 1)*3+(#a_00_19  & 1)*3+(#a_00_20  & 1)*3) >=20
 
}