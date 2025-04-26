
rule TrojanDownloader_O97M_Obfuse_BM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 0b 00 00 "
		
	strings :
		$a_01_0 = {46 69 6e 64 57 69 6e 64 6f 77 45 78 41 } //1 FindWindowExA
		$a_01_1 = {75 73 65 72 33 32 2e 64 6c 6c } //1 user32.dll
		$a_01_2 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } //1 ChrW(CLng((Not
		$a_01_3 = {44 65 62 75 67 2e 50 72 69 6e 74 } //1 Debug.Print
		$a_01_4 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 43 68 72 28 43 4c 6e 67 } //1 = Join(Array(Chr(CLng
		$a_01_5 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 22 73 47 54 47 6b 6b 34 44 54 55 6f 7a 64 65 76 39 6a 45 6a 4b 4c 67 } //1 = Len(Join(Array("sGTGkk4DTUozdev9jEjKLg
		$a_01_6 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 52 44 71 35 36 72 32 44 5f 77 59 56 30 37 61 5f 79 5a 65 65 67 41 51 5f 67 75 56 55 54 63 } //1 = Len(Join(Array(RDq56r2D_wYV07a_yZeegAQ_guVUTc
		$a_01_7 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 67 57 37 68 4e 75 74 54 6f 6c 43 49 5a 74 4d 45 68 49 34 } //1 = Len(Join(Array(gW7hNutTolCIZtMEhI4
		$a_01_8 = {3d 20 4b 6b 4e 77 41 46 36 50 47 54 53 43 46 49 32 61 78 47 69 61 35 2e 73 47 44 74 45 33 59 45 5f 59 54 37 34 55 4f 44 } //1 = KkNwAF6PGTSCFI2axGia5.sGDtE3YE_YT74UOD
		$a_01_9 = {3d 20 47 49 6f 79 5a 6a 72 36 5f 36 59 66 52 38 45 5f 4d 67 66 6a 77 64 6a 5f 6d 70 4a 39 52 4d 6a 2e 4b 66 76 57 6d 48 59 69 66 53 68 62 4a 30 } //1 = GIoyZjr6_6YfR8E_Mgfjwdj_mpJ9RMj.KfvWmHYifShbJ0
		$a_01_10 = {3d 20 56 61 4f 66 42 70 45 5f 6d 4b 58 33 75 6f 5f 49 32 6c 31 38 78 6e 2e 57 43 47 44 51 72 56 73 5f 30 58 6b 41 7a 76 65 5f 71 53 54 72 64 5a } //1 = VaOfBpE_mKX3uo_I2l18xn.WCGDQrVs_0XkAzve_qSTrdZ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=7
 
}
rule TrojanDownloader_O97M_Obfuse_BM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 0f 00 00 "
		
	strings :
		$a_01_0 = {46 69 6e 64 57 69 6e 64 6f 77 45 78 41 } //1 FindWindowExA
		$a_01_1 = {75 73 65 72 33 32 2e 64 6c 6c } //1 user32.dll
		$a_01_2 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } //1 ChrW(CLng((Not
		$a_01_3 = {44 65 62 75 67 2e 50 72 69 6e 74 } //1 Debug.Print
		$a_01_4 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 43 68 72 28 43 4c 6e 67 } //1 = Join(Array(Chr(CLng
		$a_01_5 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 5a 4f 42 59 34 38 44 64 44 37 38 6e 61 39 } //1 = Len(Join(Array(ZOBY48DdD78na9
		$a_01_6 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 53 37 4a 4a 6b 66 6c 56 6c 4b 63 30 6c 39 } //1 = Len(Join(Array(S7JJkflVlKc0l9
		$a_01_7 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 41 61 68 7a 45 4b 7a 6d 6a 50 33 59 75 38 59 32 4a 77 45 42 54 6c 6d 44 5a 72 } //1 = Len(Join(Array(AahzEKzmjP3Yu8Y2JwEBTlmDZr
		$a_01_8 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 52 47 6b 5a 43 30 4b 79 7a 30 68 76 58 51 6c 46 77 74 7a 67 54 6b 30 4a 30 6b 38 } //1 = Len(Join(Array(RGkZC0Kyz0hvXQlFwtzgTk0J0k8
		$a_01_9 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 51 72 42 46 48 32 70 46 5f 55 44 51 6b 61 44 71 5f 49 30 54 44 42 35 } //1 = Len(Join(Array(QrBFH2pF_UDQkaDq_I0TDB5
		$a_01_10 = {3d 20 4e 59 4c 30 54 61 4e 47 30 51 35 55 6e 6e 30 6d 32 39 63 41 5a 79 30 74 4e 6e 2e 5a 51 36 5a 42 63 51 79 41 65 4a 78 42 31 30 30 43 41 4f 32 42 55 } //1 = NYL0TaNG0Q5Unn0m29cAZy0tNn.ZQ6ZBcQyAeJxB100CAO2BU
		$a_01_11 = {3d 20 79 69 35 49 32 67 50 48 4d 55 69 43 68 4a 6e 78 5a 79 59 45 68 30 4c 49 68 6b 30 2e 4a 76 4f 50 37 51 6b 69 70 35 73 71 69 6d 67 47 4e 36 4a 36 76 } //1 = yi5I2gPHMUiChJnxZyYEh0LIhk0.JvOP7Qkip5sqimgGN6J6v
		$a_01_12 = {3d 20 72 7a 49 6b 30 73 34 5f 44 70 35 45 36 38 2e 74 66 70 55 6e 79 6d 37 52 46 4c 58 59 48 70 71 4d 6c 35 57 68 } //1 = rzIk0s4_Dp5E68.tfpUnym7RFLXYHpqMl5Wh
		$a_01_13 = {3d 20 66 72 36 35 65 54 30 35 5f 44 54 4e 72 6f 7a 6a 5f 30 6b 4e 36 51 72 5f 59 61 61 78 53 33 2e 79 4a 44 31 64 68 36 5f 48 70 72 73 56 55 5f 66 69 62 71 63 36 65 } //1 = fr65eT05_DTNrozj_0kN6Qr_YaaxS3.yJD1dh6_HprsVU_fibqc6e
		$a_01_14 = {3d 20 54 30 32 4b 33 63 6a 43 5f 50 38 68 31 72 53 5f 6c 48 6d 4d 62 53 42 2e 61 65 44 50 45 68 4c 57 5f 39 49 66 36 38 78 } //1 = T02K3cjC_P8h1rS_lHmMbSB.aeDPEhLW_9If68x
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=7
 
}