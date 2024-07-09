
rule Trojan_Win32_RazerPitch_A_dha{
	meta:
		description = "Trojan:Win32/RazerPitch.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 27 00 00 "
		
	strings :
		$a_01_0 = {b8 81 80 80 80 f7 e1 c1 ea 07 69 d2 ff 00 00 00 2b ca 44 0f b6 c9 30 0f 43 8d 0c 0a b8 81 80 80 80 f7 e1 c1 ea 07 69 d2 ff 00 00 00 2b ca 44 0f b6 d1 30 4f 01 48 83 c7 02 49 ff c8 } //5
		$a_03_1 = {48 83 7f 18 08 73 17 4c 8b 47 10 49 ff c0 4d 03 c0 48 8b d7 48 8b cb e8 0b 23 00 00 eb 0d 90 09 19 00 48 c7 05 ?? ?? ?? 00 07 00 00 00 48 89 ?? 26 ?? ?? 00 66 89 ?? 0f ?? ?? 00 } //5
		$a_01_2 = {5d 21 1b 07 91 99 2c c5 f5 b7 a9 61 f4 93 77 e3 e3 3f 9a d9 74 4e c2 11 93 e4 b8 9d 56 f3 4a 3e 88 c6 4f 16 65 7b e0 5c 3d 99 d6 70 47 b7 fe b6 b5 6c 22 8e b0 3f ef 2f 1f 4e 6d bb a9 e4 0e f2 0f ec 4e } //5
		$a_01_3 = {77 69 69 6e 73 65 7a 68 73 76 63 } //1 wiinsezhsvc
		$a_01_4 = {57 6c 79 74 6b 61 6e 73 76 63 2e 64 6c 6c } //1 Wlytkansvc.dll
		$a_01_5 = {74 4c 4f 55 65 6e 70 77 49 67 51 57 79 4c 6d 7a 4c 73 56 59 2e 68 4c 4e 61 70 5a 59 4e 76 74 62 76 72 73 45 49 48 6e 75 5a } //1 tLOUenpwIgQWyLmzLsVY.hLNapZYNvtbvrsEIHnuZ
		$a_01_6 = {4b 4e 68 7a 7a 6f 4c 51 43 4d 77 43 5a 50 41 42 74 70 4f 52 } //1 KNhzzoLQCMwCZPABtpOR
		$a_01_7 = {6a 2b 49 37 64 78 2f 4c 6a 36 2f 31 7a 4b 45 2b 2b 6a 49 65 35 43 57 37 4d 68 2b 48 67 69 44 48 49 62 59 46 7a 31 42 5a 53 44 52 43 57 65 35 71 43 42 35 4a 53 2b 54 35 41 50 4a 43 4c 38 73 6f 33 4e 54 79 42 6a 4d 4f 41 78 63 38 63 63 2b 4e 58 61 38 58 57 41 3d 3d } //1 j+I7dx/Lj6/1zKE++jIe5CW7Mh+HgiDHIbYFz1BZSDRCWe5qCB5JS+T5APJCL8so3NTyBjMOAxc8cc+NXa8XWA==
		$a_01_8 = {74 36 41 32 52 47 76 38 71 61 6d 31 32 58 6e 79 4b 2b 44 63 30 51 74 65 50 31 2b 50 61 6b 65 38 55 2b 56 47 55 6c 53 31 41 73 48 45 78 66 79 34 77 78 6d 4a 6a 50 57 5a 2f 33 61 4c 72 72 6b 34 } //1 t6A2RGv8qam12XnyK+Dc0QteP1+Pake8U+VGUlS1AsHExfy4wxmJjPWZ/3aLrrk4
		$a_01_9 = {33 52 35 4b 71 46 78 4e 2f 52 37 41 78 35 76 65 67 59 44 4a 6d 65 59 2b 49 68 2f 63 4b 64 51 74 2b 50 35 2b 74 69 66 4c 7a 53 59 3d } //1 3R5KqFxN/R7Ax5vegYDJmeY+Ih/cKdQt+P5+tifLzSY=
		$a_01_10 = {36 4b 63 69 7a 6c 53 56 54 58 2f 4f 72 33 4d 6b 41 6c 38 37 44 51 3d 3d } //1 6KcizlSVTX/Or3MkAl87DQ==
		$a_01_11 = {67 66 55 42 54 49 54 76 6c 6a 33 64 31 51 34 32 34 51 5a 61 69 51 3d 3d } //1 gfUBTITvlj3d1Q424QZaiQ==
		$a_01_12 = {65 50 36 53 38 36 4e 44 6c 77 6d 39 68 4f 39 45 47 2f 2f 44 33 67 3d 3d } //1 eP6S86NDlwm9hO9EG//D3g==
		$a_01_13 = {44 45 47 61 7a 33 62 62 36 74 33 79 4a 7a 51 73 4f 43 78 41 6d 56 30 36 39 65 7a 34 48 49 38 36 } //1 DEGaz3bb6t3yJzQsOCxAmV069ez4HI86
		$a_01_14 = {44 45 47 61 7a 33 62 62 36 74 33 79 4a 7a 51 73 } //1 DEGaz3bb6t3yJzQs
		$a_01_15 = {73 68 70 61 63 6e 64 73 76 63 } //1 shpacndsvc
		$a_01_16 = {53 65 7a 6c 6e 73 72 73 76 63 2e 64 6c 6c } //1 Sezlnsrsvc.dll
		$a_01_17 = {61 41 68 58 51 4d 53 50 76 6c 48 4e 51 51 4b 4d 55 71 6c 44 2e 4d 62 47 69 77 69 5a 74 50 69 75 76 44 47 73 4c 46 47 64 6c } //1 aAhXQMSPvlHNQQKMUqlD.MbGiwiZtPiuvDGsLFGdl
		$a_01_18 = {5a 79 43 50 4b 4e 4c 4d 56 50 6f 4b 4e 52 59 62 6f 55 64 74 } //1 ZyCPKNLMVPoKNRYboUdt
		$a_01_19 = {6f 6a 37 59 53 5a 4c 64 74 75 4a 66 68 65 5a 2b 32 34 56 53 74 67 43 30 7a 45 6f 69 39 46 36 67 4e 6f 7a 71 77 57 6b 4c 6b 63 55 52 35 59 6b 50 59 66 46 76 73 35 4f 2b 7a 61 59 36 5a 59 68 4f 58 57 32 34 6c 4f 4d 46 41 69 61 61 54 37 49 72 36 33 55 2b 30 51 3d 3d } //1 oj7YSZLdtuJfheZ+24VStgC0zEoi9F6gNozqwWkLkcUR5YkPYfFvs5O+zaY6ZYhOXW24lOMFAiaaT7Ir63U+0Q==
		$a_01_20 = {42 6d 4f 4f 77 42 71 5a 63 4d 68 57 49 66 2b 49 74 45 46 6d 77 77 39 65 75 39 36 47 69 43 32 31 53 4c 6e 4b 69 4b 68 4d 45 74 48 4f 50 52 61 55 35 64 6e 72 6b 6e 58 4f 50 51 39 42 64 57 38 56 } //1 BmOOwBqZcMhWIf+ItEFmww9eu96GiC21SLnKiKhMEtHOPRaU5dnrknXOPQ9BdW8V
		$a_01_21 = {51 42 4b 74 31 4a 4f 49 31 73 49 4c 53 62 55 52 2f 54 69 54 65 56 37 34 66 6d 34 79 67 7a 47 51 42 75 35 4c 32 50 35 36 52 71 55 3d } //1 QBKt1JOI1sILSbUR/TiTeV74fm4ygzGQBu5L2P56RqU=
		$a_01_22 = {78 65 6c 2f 44 36 32 42 4f 47 36 53 62 68 56 61 66 71 39 6d 4c 51 3d 3d } //1 xel/D62BOG6SbhVafq9mLQ==
		$a_01_23 = {32 50 34 5a 64 5a 39 64 32 68 6a 71 61 34 7a 7a 66 74 63 41 64 77 3d 3d } //1 2P4ZdZ9d2hjqa4zzftcAdw==
		$a_01_24 = {6e 7a 4d 2b 72 55 54 32 62 6a 4c 69 46 62 4a 43 62 6e 34 33 77 51 3d 3d } //1 nzM+rUT2bjLiFbJCbn43wQ==
		$a_01_25 = {75 6f 66 46 51 38 62 36 51 61 66 59 75 33 77 71 66 74 4c 78 31 6b 66 59 76 7a 56 57 46 49 42 75 } //1 uofFQ8b6QafYu3wqftLx1kfYvzVWFIBu
		$a_01_26 = {75 6f 66 46 51 38 62 36 51 61 66 59 75 33 77 71 } //1 uofFQ8b6QafYu3wq
		$a_01_27 = {77 62 69 73 65 70 6c 73 76 } //1 wbiseplsv
		$a_01_28 = {57 62 79 66 7a 69 6f 73 72 76 63 2e 64 6c 6c } //1 Wbyfziosrvc.dll
		$a_01_29 = {65 6e 72 79 50 46 53 6a 64 56 45 47 4f 6e 67 55 63 6b 76 44 2e 66 71 66 46 49 61 47 51 6d 42 6e 70 68 76 6e 4a 55 64 58 50 } //1 enryPFSjdVEGOngUckvD.fqfFIaGQmBnphvnJUdXP
		$a_01_30 = {51 4f 51 4e 44 6c 6a 64 42 43 56 6a 69 79 77 4c 74 47 65 4c } //1 QOQNDljdBCVjiywLtGeL
		$a_01_31 = {73 34 2b 42 37 57 37 30 50 44 35 56 49 32 44 69 63 61 71 77 57 4f 37 33 5a 4f 70 38 39 67 76 35 6e 6e 68 53 76 4e 67 5a 67 65 48 46 47 6e 79 79 6f 66 73 36 62 46 79 58 76 2f 72 74 65 69 4a 41 6b 39 32 2f 4e 72 4d 4a 57 70 77 64 4d 4d 47 64 67 4f 57 6d 6e 77 3d 3d } //1 s4+B7W70PD5VI2DicaqwWO73ZOp89gv5nnhSvNgZgeHFGnyyofs6bFyXv/rteiJAk92/NrMJWpwdMMGdgOWmnw==
		$a_01_32 = {6a 39 51 54 55 44 46 37 58 4c 2f 4a 33 61 75 74 48 4c 61 32 5a 70 37 31 57 37 75 62 59 79 72 2b 73 57 52 4d 2b 72 54 63 77 52 6f 6b 45 49 2f 4c 6a 6d 47 6c 35 2f 2f 39 56 4f 31 2b 34 46 45 37 } //1 j9QTUDF7XL/J3autHLa2Zp71W7ubYyr+sWRM+rTcwRokEI/LjmGl5//9VO1+4FE7
		$a_01_33 = {36 34 39 41 69 73 77 6a 59 42 54 78 68 70 30 34 66 53 47 31 57 4d 32 75 54 64 50 78 77 44 79 57 78 2b 42 56 47 6b 64 77 57 67 41 3d } //1 649AiswjYBTxhp04fSG1WM2uTdPxwDyWx+BVGkdwWgA=
		$a_01_34 = {52 4e 4a 37 30 45 49 37 4c 2f 6a 56 42 35 6b 39 59 57 6b 34 66 67 3d 3d } //1 RNJ70EI7L/jVB5k9YWk4fg==
		$a_01_35 = {78 70 54 67 48 54 78 6c 7a 2b 4d 7a 49 46 46 48 6f 2b 39 49 54 67 3d 3d } //1 xpTgHTxlz+MzIFFHo+9ITg==
		$a_01_36 = {41 53 67 77 6b 76 64 71 76 4a 64 53 73 72 58 6e 76 4b 36 6f 5a 67 3d 3d } //1 ASgwkvdqvJdSsrXnvK6oZg==
		$a_01_37 = {61 79 77 34 58 56 7a 71 6d 65 35 5a 50 42 6f 35 37 35 58 75 6e 48 6b 34 39 69 31 39 34 6b 34 36 } //1 ayw4XVzqme5ZPBo575XunHk49i194k46
		$a_01_38 = {61 79 77 34 58 56 7a 71 6d 65 35 5a 50 42 6f 35 } //1 ayw4XVzqme5ZPBo5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1+(#a_01_25  & 1)*1+(#a_01_26  & 1)*1+(#a_01_27  & 1)*1+(#a_01_28  & 1)*1+(#a_01_29  & 1)*1+(#a_01_30  & 1)*1+(#a_01_31  & 1)*1+(#a_01_32  & 1)*1+(#a_01_33  & 1)*1+(#a_01_34  & 1)*1+(#a_01_35  & 1)*1+(#a_01_36  & 1)*1+(#a_01_37  & 1)*1+(#a_01_38  & 1)*1) >=5
 
}