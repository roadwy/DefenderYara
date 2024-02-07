
rule Trojan_Win32_Adclicker_A{
	meta:
		description = "Trojan:Win32/Adclicker.A,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 19 00 00 04 00 "
		
	strings :
		$a_00_0 = {2f 63 70 61 2f 61 64 73 3f } //04 00  /cpa/ads?
		$a_00_1 = {2e 63 6e 2f 61 64 73 2f 61 64 73 2e 61 73 70 3f } //04 00  .cn/ads/ads.asp?
		$a_00_2 = {5f 30 61 64 73 5f 61 6c } //04 00  _0ads_al
		$a_00_3 = {26 61 64 5f 74 79 70 65 3d } //04 00  &ad_type=
		$a_00_4 = {73 65 6f 3d } //05 00  seo=
		$a_00_5 = {6d 69 63 72 30 73 30 66 74 2e 63 6f 6d } //05 00  micr0s0ft.com
		$a_00_6 = {6a 6f 79 6f 2e 63 6f 6d 2f 64 65 66 61 75 6c 74 2e 61 73 70 3f 73 6f 75 72 63 65 3d 61 64 34 61 6c 6c } //05 00  joyo.com/default.asp?source=ad4all
		$a_00_7 = {66 65 69 67 6f 75 2e 69 6e 69 } //01 00  feigou.ini
		$a_02_8 = {63 6c 69 65 6e 74 3d 63 61 2d 70 75 62 2d 90 0f 0c 00 90 00 } //01 00 
		$a_00_9 = {63 70 72 6f 2e 62 61 69 64 75 2e 63 6f 6d } //01 00  cpro.baidu.com
		$a_00_10 = {61 73 69 61 66 69 6e 64 2e 63 6f 6d } //01 00  asiafind.com
		$a_00_11 = {66 75 63 6b 2e 61 73 70 } //01 00  fuck.asp
		$a_00_12 = {61 64 63 6c 69 65 6e 74 2e 63 68 69 6e 61 2e 63 6f 6d } //01 00  adclient.china.com
		$a_00_13 = {61 64 73 2e 63 68 69 6e 61 2e 63 6f 6d } //01 00  ads.china.com
		$a_00_14 = {61 64 2e 74 6f 6d 2e 63 6f 6d } //01 00  ad.tom.com
		$a_02_15 = {61 64 73 76 69 65 77 90 01 01 2e 71 71 2e 63 6f 6d 90 00 } //01 00 
		$a_00_16 = {61 64 73 2e 61 64 62 72 69 74 65 2e 63 6f 6d } //01 00  ads.adbrite.com
		$a_00_17 = {61 64 2e 79 69 67 61 6f 2e 63 6f 6d } //01 00  ad.yigao.com
		$a_00_18 = {61 64 73 38 2e 63 6f 6d } //01 00  ads8.com
		$a_00_19 = {6d 6f 6b 61 61 64 73 2e 6c 69 6e 6b 61 64 2e 63 6e } //01 00  mokaads.linkad.cn
		$a_00_20 = {61 64 73 75 6e 69 6f 6e 2e 63 6f 6d } //03 00  adsunion.com
		$a_00_21 = {52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 77 77 77 2e 78 78 78 2e 63 6f 6d } //03 00  Referer: http://www.xxx.com
		$a_00_22 = {52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 77 77 77 2e 35 31 36 32 36 2e 6e 65 74 } //03 00  Referer: http://www.51626.net
		$a_00_23 = {52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 74 67 2e 73 64 6f 2e 63 6f 6d } //03 00  Referer: http://tg.sdo.com
		$a_00_24 = {52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 77 77 77 2e 6e 65 74 78 62 6f 79 2e 63 6f 6d } //00 00  Referer: http://www.netxboy.com
	condition:
		any of ($a_*)
 
}