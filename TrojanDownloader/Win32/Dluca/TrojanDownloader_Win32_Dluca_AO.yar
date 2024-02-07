
rule TrojanDownloader_Win32_Dluca_AO{
	meta:
		description = "TrojanDownloader:Win32/Dluca.AO,SIGNATURE_TYPE_PEHSTR,14 00 14 00 24 00 00 05 00 "
		
	strings :
		$a_01_0 = {43 46 44 41 54 41 2e 69 6d 61 3f 63 63 6f 64 65 3d 25 73 26 63 66 64 61 74 61 63 63 3d 25 73 26 67 6d 74 3d 25 64 } //05 00  CFDATA.ima?ccode=%s&cfdatacc=%s&gmt=%d
		$a_01_1 = {26 69 76 68 3d 25 64 26 64 76 68 3d 25 64 26 69 76 6c 3d 25 64 26 64 76 6c 3d 25 64 26 69 64 3d 25 73 } //05 00  &ivh=%d&dvh=%d&ivl=%d&dvl=%d&id=%s
		$a_01_2 = {25 73 77 6b 2f 67 65 74 63 6c 69 65 6e 74 69 64 2e 77 6e 6b 3f 73 72 76 3d 25 73 26 76 65 72 3d 25 73 } //05 00  %swk/getclientid.wnk?srv=%s&ver=%s
		$a_01_3 = {25 73 77 6b 2f 67 65 74 63 6c 69 65 6e 74 69 6e 66 6f 2e 77 6e 6b 3f 69 64 3d 25 73 26 73 72 76 3d 25 73 26 76 65 72 3d 25 73 26 64 6f 63 69 64 3d 25 73 26 74 69 6d 65 3d 25 64 26 63 73 74 61 74 65 3d 25 64 26 73 74 61 74 65 3d 25 73 26 66 6c 61 73 68 3d 25 73 } //05 00  %swk/getclientinfo.wnk?id=%s&srv=%s&ver=%s&docid=%s&time=%d&cstate=%d&state=%s&flash=%s
		$a_01_4 = {63 70 76 2e 6a 73 70 3f 70 3d 31 31 30 39 35 36 26 72 65 73 70 6f 6e 73 65 3d 78 6d 6c 26 75 72 6c 3d 25 73 26 63 6f 6e 74 65 78 74 3d 25 73 26 72 6f 6e 3d 6f 66 66 } //01 00  cpv.jsp?p=110956&response=xml&url=%s&context=%s&ron=off
		$a_01_5 = {25 73 25 73 40 61 64 74 72 67 74 2e 63 6f 6d 2f } //01 00  %s%s@adtrgt.com/
		$a_01_6 = {25 73 25 73 40 70 6f 70 75 6e 64 65 72 2e 61 64 74 72 67 74 2e 63 6f 6d 2f } //01 00  %s%s@popunder.adtrgt.com/
		$a_01_7 = {25 73 25 73 40 75 72 6c 2e 61 64 74 72 67 74 2e 63 6f 6d 2f } //01 00  %s%s@url.adtrgt.com/
		$a_01_8 = {25 73 3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 } //01 00  %s:Zone.Identifier
		$a_01_9 = {25 73 5c 73 79 73 74 65 6d 5c 25 73 2e 65 78 65 } //01 00  %s\system\%s.exe
		$a_01_10 = {25 73 7e 63 66 64 61 74 61 2e 74 78 74 } //01 00  %s~cfdata.txt
		$a_01_11 = {25 31 39 35 2e 38 2e 31 35 2e 31 33 38 } //01 00  %195.8.15.138
		$a_01_12 = {32 31 37 2e 31 34 35 2e 37 36 2e 31 33 } //01 00  217.145.76.13
		$a_01_13 = {25 61 6f 6c 73 65 61 72 63 68 2e 61 6f 6c 2e 63 6f 6d } //01 00  %aolsearch.aol.com
		$a_01_14 = {63 6e 65 74 2e 63 6f 6d } //01 00  cnet.com
		$a_01_15 = {66 72 65 65 70 6f 72 6e 6e 6f 77 2e 6e 65 74 } //01 00  freepornnow.net
		$a_01_16 = {66 72 65 65 70 6f 72 6e 74 6f 64 61 79 2e 6e 65 74 } //01 00  freeporntoday.net
		$a_01_17 = {6b 6a 64 68 65 6e 64 69 65 6c 64 69 6f 75 79 75 2e 63 6f 6d } //01 00  kjdhendieldiouyu.com
		$a_01_18 = {6d 79 73 70 61 63 65 2e 63 6f 6d } //01 00  myspace.com
		$a_01_19 = {70 6f 72 6e 31 2e 6f 72 67 } //01 00  porn1.org
		$a_01_20 = {73 65 61 2e 73 65 61 72 63 68 2e 6d 73 6e 2e 63 6f 6d } //01 00  sea.search.msn.com
		$a_01_21 = {73 65 61 72 63 68 2e 61 6f 6c 2e 63 6f 6d } //01 00  search.aol.com
		$a_01_22 = {73 65 61 72 63 68 2e 6c 69 76 65 2e 63 6f 6d } //01 00  search.live.com
		$a_01_23 = {73 65 61 72 63 68 2e 6c 79 63 6f 73 2e 63 6f 6d } //01 00  search.lycos.com
		$a_01_24 = {73 65 61 72 63 68 2e 6d 73 6e 2e 63 6f 6d } //01 00  search.msn.com
		$a_01_25 = {73 65 61 72 63 68 2e 6e 65 74 73 63 61 70 65 2e 63 6f 6d } //01 00  search.netscape.com
		$a_01_26 = {73 65 61 72 63 68 2e 79 61 68 6f 6f 2e 63 6f 6d } //01 00  search.yahoo.com
		$a_01_27 = {73 77 65 65 70 73 74 61 6b 65 73 73 2e 63 6f 6d } //01 00  sweepstakess.com
		$a_01_28 = {76 69 72 67 69 6e 73 2e 67 72 } //01 00  virgins.gr
		$a_01_29 = {76 69 72 67 69 6e 73 2e 6c 74 } //01 00  virgins.lt
		$a_01_30 = {76 69 72 67 69 6e 73 2e 73 65 } //01 00  virgins.se
		$a_01_31 = {77 77 77 2e 61 6c 74 61 76 69 73 74 61 2e 63 6f 6d } //01 00  www.altavista.com
		$a_01_32 = {77 77 77 2e 67 6f 6f 67 6c 65 2e } //01 00  www.google.
		$a_01_33 = {77 77 77 2e 6c 69 76 65 2e 63 6f 6d } //01 00  www.live.com
		$a_01_34 = {77 77 77 2e 73 65 61 72 63 68 2e 63 6f 6d } //01 00  www.search.com
		$a_01_35 = {77 77 77 2e 79 61 68 6f 6f 2e 63 6f 6d } //00 00  www.yahoo.com
	condition:
		any of ($a_*)
 
}