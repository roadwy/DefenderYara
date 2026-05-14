
rule Trojan_BAT_Xworm_MK_MTB{
	meta:
		description = "Trojan:BAT/Xworm.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,46 00 46 00 04 00 00 "
		
	strings :
		$a_01_0 = {20 29 41 00 00 20 44 ab 00 00 61 26 20 c4 7a 01 00 20 2e ed 00 00 59 26 20 66 10 00 00 20 e8 d6 00 00 58 26 20 a8 fb 00 00 20 ec 30 01 00 58 26 } //25
		$a_81_1 = {43 20 47 21 49 22 4d 23 4f 24 52 25 55 26 59 27 5c 28 5e 29 62 2a 65 2b 68 2c 6a 2d 6e 2e 71 2f 73 30 75 31 77 32 7a 33 7c 34 } //20 C G!I"M#O$R%U&Y'\(^)b*e+h,j-n.q/s0u1w2z3|4
		$a_81_2 = {58 34 77 62 74 55 41 45 42 4c 6b 53 42 4d 4e 4c 66 32 4b 61 33 41 3d 3d } //15 X4wbtUAEBLkSBMNLf2Ka3A==
		$a_01_3 = {71 44 32 4e 61 6c 45 76 4c 6d 2f 59 48 4d 67 34 6a 51 67 4a 64 33 35 48 65 4d 45 54 61 36 6a 45 51 64 5a 50 32 61 4e 44 31 6d 4f 34 36 73 63 65 47 77 7a 66 6c 57 6f 74 68 30 4c 2b 37 43 73 75 79 76 6a 6c 4c 6a 76 44 77 38 4d 69 53 35 45 70 79 75 4e 70 35 4d 72 34 35 53 34 37 } //10 qD2NalEvLm/YHMg4jQgJd35HeMETa6jEQdZP2aND1mO46sceGwzflWoth0L+7CsuyvjlLjvDw8MiS5EpyuNp5Mr45S47
	condition:
		((#a_01_0  & 1)*25+(#a_81_1  & 1)*20+(#a_81_2  & 1)*15+(#a_01_3  & 1)*10) >=70
 
}