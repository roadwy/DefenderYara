
rule TrojanDownloader_O97M_Dridex_AJV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.AJV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 4d 69 73 20 3d 20 53 70 6c 69 74 28 52 54 72 69 6d 28 76 5f 6d 61 6c 6c 5f 61 28 76 5f 6d 61 6c 6c 5f 61 28 43 65 6c 6c 73 28 32 30 30 2c 20 31 30 29 29 29 29 2c 20 67 72 61 70 68 5f 7a 6f 6f 6d 28 22 21 22 2c 20 35 29 29 } //1 cMis = Split(RTrim(v_mall_a(v_mall_a(Cells(200, 10)))), graph_zoom("!", 5))
		$a_01_1 = {53 68 65 65 74 73 28 31 29 2e 43 65 6c 6c 73 28 33 2c 20 31 29 2e 4e 61 6d 65 20 3d 20 22 5a 6f 6f 6d 5f 22 20 26 20 22 61 6e 64 22 } //1 Sheets(1).Cells(3, 1).Name = "Zoom_" & "and"
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 28 22 5a 6f 6f 6d 5f 22 20 26 20 22 61 6e 64 22 29 } //1 Application.Run ("Zoom_" & "and")
		$a_01_3 = {65 6d 61 69 6c 5f 63 6c 69 65 6e 74 20 30 2c 20 6e 65 78 74 5f 6f 72 64 65 72 73 28 6f 6e 65 5f 70 72 69 63 65 28 53 70 6c 69 74 28 63 4d 69 73 28 30 29 2c 20 22 47 47 22 20 26 20 22 22 29 29 29 2c 20 45 63 68 6f 4f 6e 65 20 26 20 22 5c 22 20 26 20 62 62 42 61 72 73 2c 20 30 2c 20 30 } //1 email_client 0, next_orders(one_price(Split(cMis(0), "GG" & ""))), EchoOne & "\" & bbBars, 0, 0
		$a_01_4 = {67 72 61 70 68 5f 7a 6f 6f 6d 20 3d 20 52 65 70 6c 61 63 65 28 53 74 72 69 6e 67 28 74 2c 20 43 78 29 2c 20 43 78 2c 20 75 29 } //1 graph_zoom = Replace(String(t, Cx), Cx, u)
		$a_01_5 = {6e 65 78 74 5f 6f 72 64 65 72 73 20 3d 20 22 68 74 74 22 20 26 20 22 70 22 20 26 20 22 73 3a 2f 2f 22 20 26 20 76 76 } //1 next_orders = "htt" & "p" & "s://" & vv
		$a_01_6 = {3d 20 53 70 6c 69 74 28 65 2c 20 67 72 61 70 68 5f 7a 6f 6f 6d 28 22 2b 22 2c 20 34 29 29 } //1 = Split(e, graph_zoom("+", 4))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}