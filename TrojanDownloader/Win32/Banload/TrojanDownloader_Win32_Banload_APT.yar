
rule TrojanDownloader_Win32_Banload_APT{
	meta:
		description = "TrojanDownloader:Win32/Banload.APT,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {7e 72 5b 65 5d 67 7e 20 5b 61 5d 64 5b 64 7e 20 5b } //1 ~r[e]g~ [a]d[d~ [
		$a_01_1 = {7e 52 5d 75 7e 6e 5e 44 7e 4c 5e 4c 5e 33 5d 32 5d } //1 ~R]u~n^D~L^L^3]2]
		$a_01_2 = {5e 68 7e 74 5b 74 7e 70 7e 3a 5d 2f 7e 2f 7e } //1 ^h~t[t~p~:]/~/~
		$a_01_3 = {5b 2e 5d 63 5d 70 7e 6c 5b } //1 [.]c]p~l[
		$a_01_4 = {7e 41 5d 76 5b 69 7e 72 7e 61 } //1 ~A]v[i~r~a
		$a_01_5 = {5b 41 5e 76 7e 67 5d 54 5e 72 5d 61 5b 79 } //1 [A^v~g]T^r]a[y
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}