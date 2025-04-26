
rule TrojanDownloader_O97M_Dridex_RVE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.RVE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {41 63 74 69 6f 6e 2e 41 72 67 75 6d 65 6e 74 73 20 3d 20 4d 6f 64 75 6c 65 32 2e 75 5f 74 65 5f 70 7a 6e 65 71 64 75 74 63 28 6b 62 66 65 74 70 67 69 78 75 69 70 65 67 62 29 20 26 20 4d 6f 64 75 6c 65 32 2e 65 6b 65 5f 6c 72 6a 7a 74 79 5f 6e 79 67 28 61 6c 69 6f 61 6d 5f 64 5f 76 68 67 71 72 6d 29 20 } //1 Action.Arguments = Module2.u_te_pzneqdutc(kbfetpgixuipegb) & Module2.eke_lrjzty_nyg(alioam_d_vhgqrm) 
		$a_01_1 = {41 63 74 69 6f 6e 2e 41 72 67 75 6d 65 6e 74 73 20 3d 20 4d 6f 64 75 6c 65 32 2e 71 70 75 66 64 6a 5f 61 68 6b 5f 78 61 28 62 6d 72 71 78 6d 7a 6e 6d 66 6a 5f 6d 77 29 20 26 20 4d 6f 64 75 6c 65 33 2e 71 6b 62 66 64 6a 5f 63 7a 78 6d 72 6f 6f 28 7a 61 78 74 6e 61 63 69 68 6d 79 71 79 6c 68 29 } //1 Action.Arguments = Module2.qpufdj_ahk_xa(bmrqxmznmfj_mw) & Module3.qkbfdj_czxmroo(zaxtnacihmyqylh)
		$a_01_2 = {41 63 74 69 6f 6e 2e 41 72 67 75 6d 65 6e 74 73 20 3d 20 4d 6f 64 75 6c 65 32 2e 77 65 74 75 77 77 65 71 76 6e 67 5f 78 6b 28 64 6e 5f 66 75 77 5f 5f 70 76 64 6f 5f 79 29 20 26 20 4d 6f 64 75 6c 65 33 2e 77 61 66 71 61 66 78 6f 6b 62 5f 69 72 6e 68 28 70 6b 5f 74 72 73 70 6c 75 76 5f 76 77 75 68 29 } //1 Action.Arguments = Module2.wetuwweqvng_xk(dn_fuw__pvdo_y) & Module3.wafqafxokb_irnh(pk_trspluv_vwuh)
		$a_01_3 = {41 63 74 69 6f 6e 2e 41 72 67 75 6d 65 6e 74 73 20 3d 20 4d 6f 64 75 6c 65 32 2e 7a 6e 6b 61 77 65 65 62 6c 76 75 67 7a 61 67 28 63 6d 74 69 69 5f 6b 6f 5f 77 63 73 6b 66 29 20 26 20 4d 6f 64 75 6c 65 32 2e 68 6e 62 63 6f 77 6c 6b 66 6e 6e 63 67 6a 78 28 74 62 7a 67 68 64 71 6e 5f 70 75 79 66 69 29 } //1 Action.Arguments = Module2.znkaweeblvugzag(cmtii_ko_wcskf) & Module2.hnbcowlkfnncgjx(tbzghdqn_puyfi)
		$a_01_4 = {43 61 6c 6c 20 72 6f 6f 74 46 6f 6c 64 65 72 2e 52 65 67 69 73 74 65 72 54 61 73 6b 44 65 66 69 6e 69 74 69 6f 6e 28 20 5f 0d 0a 20 20 20 20 22 54 65 73 74 20 54 69 6d 65 54 72 69 67 67 65 72 22 2c 20 74 61 73 6b 44 65 66 69 6e 69 74 69 6f 6e 2c 20 36 2c 20 2c 20 2c 20 33 29 } //1
		$a_01_5 = {74 72 69 67 67 65 72 2e 45 78 65 63 75 74 69 6f 6e 54 69 6d 65 4c 69 6d 69 74 20 3d 20 22 50 54 35 4d 22 } //1 trigger.ExecutionTimeLimit = "PT5M"
		$a_01_6 = {73 65 72 76 69 63 65 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 68 65 64 75 6c 65 2e 53 65 72 76 69 63 65 22 29 } //1 service = CreateObject("Schedule.Service")
		$a_01_7 = {74 69 6d 65 20 3d 20 44 61 74 65 41 64 64 28 22 6e 22 2c 20 31 30 2c 20 4e 6f 77 29 } //1 time = DateAdd("n", 10, Now)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}