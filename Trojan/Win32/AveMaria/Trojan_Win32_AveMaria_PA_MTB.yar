
rule Trojan_Win32_AveMaria_PA_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.PA!MTB,SIGNATURE_TYPE_PEHSTR,17 00 17 00 2b 00 00 04 00 "
		
	strings :
		$a_01_0 = {41 56 45 5f 4d 41 52 49 41 } //04 00  AVE_MARIA
		$a_01_1 = {4b 4c 47 6c 6f 67 2e 74 78 74 } //01 00  KLGlog.txt
		$a_01_2 = {43 41 52 44 20 4e 55 4d 42 45 52 3a } //01 00  CARD NUMBER:
		$a_01_3 = {43 41 52 44 48 4f 4c 44 45 52 20 4e 41 4d 45 3a } //01 00  CARDHOLDER NAME:
		$a_01_4 = {22 2c 4b 4c 47 3a 22 } //01 00  ",KLG:"
		$a_01_5 = {22 2c 53 54 4c 3a 22 } //01 00  ",STL:"
		$a_01_6 = {22 2c 41 56 3a 22 } //01 00  ",AV:"
		$a_01_7 = {22 2c 63 6f 6c 64 77 61 6c 6c 65 74 73 3a } //01 00  ",coldwallets:
		$a_01_8 = {75 70 64 61 74 65 62 6f 74 } //01 00  updatebot
		$a_01_9 = {72 65 73 74 61 72 74 62 6f 74 } //01 00  restartbot
		$a_01_10 = {67 65 74 73 63 72 65 65 6e } //01 00  getscreen
		$a_01_11 = {73 74 61 72 74 6b 6c 67 } //01 00  startklg
		$a_01_12 = {6b 69 6c 6c 70 72 6f 63 65 73 73 } //01 00  killprocess
		$a_01_13 = {73 74 61 72 74 61 73 61 64 6d 69 6e 65 78 65 } //01 00  startasadminexe
		$a_01_14 = {64 58 42 6b 59 58 52 6c 59 6d 39 30 } //01 00  dXBkYXRlYm90
		$a_01_15 = {63 6d 56 7a 64 47 46 79 64 47 4a 76 64 41 3d 3d } //01 00  cmVzdGFydGJvdA==
		$a_01_16 = {5a 32 56 30 63 32 4e 79 5a 57 56 75 } //01 00  Z2V0c2NyZWVu
		$a_01_17 = {63 33 52 68 63 6e 52 72 62 47 63 3d } //01 00  c3RhcnRrbGc=
		$a_01_18 = {61 32 6c 73 62 48 42 79 62 32 4e 6c 63 33 4d 3d } //01 00  a2lsbHByb2Nlc3M=
		$a_01_19 = {63 33 52 68 63 6e 52 68 63 32 46 6b 62 57 6c 75 5a 58 68 6c } //01 00  c3RhcnRhc2FkbWluZXhl
		$a_01_20 = {63 32 68 31 64 47 52 76 64 32 35 77 59 77 3d 3d } //01 00  c2h1dGRvd25wYw==
		$a_01_21 = {5a 32 56 30 63 33 52 73 } //01 00  Z2V0c3Rs
		$a_01_22 = {61 58 4e 33 62 33 4a 72 61 32 78 6e } //01 00  aXN3b3Jra2xn
		$a_01_23 = {5a 47 39 33 62 6d 78 76 59 57 52 6d 61 57 78 6c } //01 00  ZG93bmxvYWRmaWxl
		$a_01_24 = {63 61 72 64 5f 6e 75 6d 62 65 72 5f 65 6e 63 72 79 70 74 65 64 } //01 00  card_number_encrypted
		$a_01_25 = {63 72 65 64 69 74 5f 63 61 72 64 73 } //01 00  credit_cards
		$a_01_26 = {50 00 68 00 6f 00 65 00 6e 00 69 00 78 00 63 00 6f 00 69 00 6e 00 } //01 00  Phoenixcoin
		$a_01_27 = {42 00 79 00 74 00 65 00 63 00 6f 00 69 00 6e 00 } //01 00  Bytecoin
		$a_01_28 = {4c 00 75 00 63 00 6b 00 79 00 63 00 6f 00 69 00 6e 00 } //01 00  Luckycoin
		$a_01_29 = {49 00 30 00 63 00 6f 00 69 00 6e 00 } //01 00  I0coin
		$a_01_30 = {6d 00 6f 00 6e 00 65 00 72 00 6f 00 2d 00 77 00 61 00 6c 00 6c 00 65 00 74 00 2d 00 67 00 75 00 69 00 } //01 00  monero-wallet-gui
		$a_01_31 = {45 00 74 00 68 00 65 00 72 00 65 00 75 00 6d 00 } //01 00  Ethereum
		$a_01_32 = {5c 00 59 00 61 00 6e 00 64 00 65 00 78 00 5c 00 59 00 61 00 6e 00 64 00 65 00 78 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5c 00 } //01 00  \Yandex\YandexBrowser\
		$a_01_33 = {5c 00 33 00 36 00 30 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5c 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 } //01 00  \360Browser\Browser
		$a_01_34 = {5c 00 53 00 70 00 75 00 74 00 6e 00 69 00 6b 00 5c 00 53 00 70 00 75 00 74 00 6e 00 69 00 6b 00 } //01 00  \Sputnik\Sputnik
		$a_01_35 = {5c 00 43 00 6f 00 63 00 43 00 6f 00 63 00 5c 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 } //01 00  \CocCoc\Browser
		$a_01_36 = {5c 00 75 00 43 00 6f 00 7a 00 4d 00 65 00 64 00 69 00 61 00 5c 00 55 00 72 00 61 00 6e 00 5c 00 } //01 00  \uCozMedia\Uran\
		$a_01_37 = {5c 00 43 00 6f 00 6d 00 6f 00 64 00 6f 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 6f 00 64 00 6f 00 5c 00 } //01 00  \Comodo\Chromodo\
		$a_01_38 = {58 46 78 44 62 32 31 76 5a 47 39 63 58 45 4e 6f 63 6d 39 74 62 32 52 76 58 46 78 56 63 32 56 79 49 45 52 68 64 47 46 63 58 41 3d 3d } //01 00  XFxDb21vZG9cXENocm9tb2RvXFxVc2VyIERhdGFcXA==
		$a_01_39 = {58 46 78 56 51 30 4a 79 62 33 64 7a 5a 58 4a 63 58 46 56 7a 5a 58 49 67 52 47 46 30 59 56 39 70 4d 54 68 75 58 46 77 3d } //01 00  XFxVQ0Jyb3dzZXJcXFVzZXIgRGF0YV9pMThuXFw=
		$a_01_40 = {58 46 78 56 51 30 4a 79 62 33 64 7a 5a 58 4a 63 58 46 56 7a 5a 58 49 67 52 47 46 30 59 56 39 6c 62 69 31 56 55 31 78 63 } //01 00  XFxVQ0Jyb3dzZXJcXFVzZXIgRGF0YV9lbi1VU1xc
		$a_01_41 = {58 46 78 56 51 30 4a 79 62 33 64 7a 5a 58 4a 63 58 46 56 7a 5a 58 49 67 52 47 46 30 59 56 39 79 64 53 31 53 56 56 78 63 } //01 00  XFxVQ0Jyb3dzZXJcXFVzZXIgRGF0YV9ydS1SVVxc
		$a_01_42 = {58 46 78 43 63 6d 39 74 61 58 56 74 58 46 78 56 63 32 56 79 49 45 52 68 64 47 46 63 58 41 3d 3d } //00 00  XFxCcm9taXVtXFxVc2VyIERhdGFcXA==
	condition:
		any of ($a_*)
 
}