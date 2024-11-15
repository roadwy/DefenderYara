
rule Trojan_Win32_Neoreblamy_BAA_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 20 00 00 "
		
	strings :
		$a_01_0 = {4b 59 42 6f 6e 48 75 67 4c 49 56 42 56 4b 5a 7a 4b 70 47 56 68 77 68 74 6a 4b 43 74 47 51 } //1 KYBonHugLIVBVKZzKpGVhwhtjKCtGQ
		$a_01_1 = {64 4c 59 46 62 71 45 51 6a 73 78 6e 52 69 67 51 4d 71 78 77 55 4a 7a 76 54 4a 5a 68 61 71 } //1 dLYFbqEQjsxnRigQMqxwUJzvTJZhaq
		$a_01_2 = {4e 67 6a 4d 68 6d 51 67 72 70 75 7a 4f 64 47 41 48 73 48 75 69 55 4e 4b 51 58 6d 77 52 48 65 51 56 6c } //1 NgjMhmQgrpuzOdGAHsHuiUNKQXmwRHeQVl
		$a_01_3 = {42 6e 49 79 4d 68 79 76 6d 6c 4d 55 66 64 61 51 53 59 46 54 4e 55 4d 54 56 4a 64 77 78 64 64 58 48 72 6e 4e } //1 BnIyMhyvmlMUfdaQSYFTNUMTVJdwxddXHrnN
		$a_01_4 = {54 75 59 47 75 43 66 46 6f 6a 58 74 50 77 59 59 43 51 4e 4f 62 71 50 68 65 6b 44 5a 58 53 } //1 TuYGuCfFojXtPwYYCQNObqPhekDZXS
		$a_01_5 = {76 6d 47 55 61 77 49 47 6e 4b 64 49 67 7a 6a 68 7a 41 47 65 79 75 4c 48 43 48 44 5a } //1 vmGUawIGnKdIgzjhzAGeyuLHCHDZ
		$a_01_6 = {75 57 62 66 62 64 4d 49 77 4a 41 72 79 57 48 61 47 4d 71 58 78 4c 76 6a 50 45 65 5a 77 75 67 67 48 55 } //1 uWbfbdMIwJAryWHaGMqXxLvjPEeZwuggHU
		$a_01_7 = {6a 54 74 65 52 4f 50 45 65 69 6e 65 4f 51 6c 4b 42 70 4c 43 6f 6f 6e 70 79 41 48 47 71 45 45 4f 4e 72 6d 6e } //1 jTteROPEeineOQlKBpLCoonpyAHGqEEONrmn
		$a_01_8 = {73 65 79 4f 43 73 47 5a 57 63 6a 61 64 41 4b 58 78 51 48 50 61 75 70 70 56 43 54 65 4c 6d } //1 seyOCsGZWcjadAKXxQHPauppVCTeLm
		$a_01_9 = {51 50 78 4a 76 4f 42 6b 55 76 50 41 45 61 50 72 61 78 45 72 6d 79 46 63 44 78 48 68 } //1 QPxJvOBkUvPAEaPraxErmyFcDxHh
		$a_01_10 = {5a 42 64 62 48 65 57 44 6d 62 50 4f 72 52 41 4f 73 6f 4b 4d 74 49 52 4b 53 57 76 7a 65 4b 63 74 58 4b } //1 ZBdbHeWDmbPOrRAOsoKMtIRKSWvzeKctXK
		$a_01_11 = {52 55 55 71 71 6c 6a 78 65 53 57 4e 55 6a 48 43 68 67 52 54 55 71 74 74 76 41 48 67 50 49 71 51 4e 44 6e 6a 65 } //1 RUUqqljxeSWNUjHChgRTUqttvAHgPIqQNDnje
		$a_01_12 = {75 77 57 73 65 53 4b 4d 45 42 6e 76 6f 44 6e 57 4f 52 44 7a 45 65 5a 63 58 4d 4d 6e } //1 uwWseSKMEBnvoDnWORDzEeZcXMMn
		$a_01_13 = {77 6d 44 50 79 56 48 6d 5a 49 68 51 63 51 4b 67 50 43 6c 4f 74 4c 54 76 52 49 45 6a } //1 wmDPyVHmZIhQcQKgPClOtLTvRIEj
		$a_01_14 = {69 50 45 64 51 6b 7a 72 68 49 52 68 56 4f 6c 51 62 71 4c 65 72 63 45 73 5a 49 73 65 55 67 } //1 iPEdQkzrhIRhVOlQbqLercEsZIseUg
		$a_01_15 = {75 54 79 66 6a 6c 52 51 72 65 79 69 71 73 4f 6a 72 70 56 47 62 75 68 44 68 76 51 4a 45 65 50 4d 57 43 } //1 uTyfjlRQreyiqsOjrpVGbuhDhvQJEePMWC
		$a_01_16 = {63 75 42 79 53 4f 72 79 58 4c 6b 41 6e 71 42 56 74 6b 65 41 6c 50 58 62 52 7a 58 70 } //1 cuBySOryXLkAnqBVtkeAlPXbRzXp
		$a_01_17 = {67 64 61 56 75 74 56 56 46 48 70 7a 44 59 4b 71 69 6f 43 4e 6a 69 4e 43 64 64 45 47 47 66 59 59 6d 50 } //1 gdaVutVVFHpzDYKqioCNjiNCddEGGfYYmP
		$a_01_18 = {43 69 69 71 70 77 63 48 4e 4d 6f 78 51 4b 4d 46 77 45 4e 53 58 74 4c 57 76 62 42 71 72 } //1 CiiqpwcHNMoxQKMFwENSXtLWvbBqr
		$a_01_19 = {71 6d 76 56 48 42 74 4e 42 73 71 6a 4d 6b 45 70 76 65 4a 71 4f 61 45 6a 56 4e 48 78 78 61 55 6c 64 6c } //1 qmvVHBtNBsqjMkEpveJqOaEjVNHxxaUldl
		$a_01_20 = {54 49 4b 4a 65 64 55 77 65 58 51 5a 4a 4b 71 47 66 48 58 79 42 53 44 77 75 65 75 6c } //1 TIKJedUweXQZJKqGfHXyBSDwueul
		$a_01_21 = {55 61 75 48 42 52 6a 4b 48 6e 44 62 54 78 42 49 53 56 44 65 55 4c 4c 6e 65 67 6d 7a } //1 UauHBRjKHnDbTxBISVDeULLnegmz
		$a_01_22 = {66 47 79 41 70 68 68 4e 4a 73 6e 49 59 54 45 4c 50 6d 54 46 46 4f 50 45 74 68 4e 66 6c 6a 44 6c 42 4a } //1 fGyAphhNJsnIYTELPmTFFOPEthNfljDlBJ
		$a_01_23 = {51 7a 7a 68 68 4b 50 57 4f 51 6e 4d 63 69 44 78 6c 6f 55 4f 6f 44 6e 4f 42 45 50 66 44 6c 49 44 48 } //1 QzzhhKPWOQnMciDxloUOoDnOBEPfDlIDH
		$a_01_24 = {4f 43 65 4a 46 69 49 51 6f 4d 4b 55 4f 5a 53 69 45 59 5a 62 63 77 5a 53 4a 6e 4e 73 72 47 } //1 OCeJFiIQoMKUOZSiEYZbcwZSJnNsrG
		$a_01_25 = {73 69 72 47 4b 6b 6c 51 4b 52 57 59 4f 46 68 55 56 41 51 48 43 47 6d 6c 41 67 62 45 } //1 sirGKklQKRWYOFhUVAQHCGmlAgbE
		$a_01_26 = {4c 42 64 6d 51 6d 70 49 6e 72 56 57 64 68 47 47 4e 6a 4f 62 6d 48 53 41 47 70 68 43 64 64 63 78 74 65 } //1 LBdmQmpInrVWdhGGNjObmHSAGphCddcxte
		$a_01_27 = {4b 54 4e 78 48 62 6b 6e 79 4b 61 79 54 69 51 76 74 57 79 41 52 42 52 4c 69 79 65 73 4e } //1 KTNxHbknyKayTiQvtWyARBRLiyesN
		$a_01_28 = {4a 43 67 5a 76 4f 64 76 54 66 75 6d 62 4a 67 76 65 49 71 43 79 68 76 50 72 53 4e 4d 79 62 } //1 JCgZvOdvTfumbJgveIqCyhvPrSNMyb
		$a_01_29 = {6d 46 48 42 6d 5a 69 6c 6b 57 73 68 4c 57 6c 51 56 62 55 54 59 59 53 59 70 76 4f 67 } //1 mFHBmZilkWshLWlQVbUTYYSYpvOg
		$a_01_30 = {61 51 73 4a 52 4c 79 48 47 75 59 43 6d 4f 54 6a 67 5a 77 4c 43 52 47 53 6a 72 54 63 65 72 6e 6e 7a 55 } //1 aQsJRLyHGuYCmOTjgZwLCRGSjrTcernnzU
		$a_01_31 = {6a 53 7a 6d 4d 64 54 68 46 62 71 68 65 4d 64 67 4c 63 6a 6f 4b 4b 43 41 64 48 51 53 54 68 62 7a 68 61 4d 76 46 49 76 } //1 jSzmMdThFbqheMdgLcjoKKCAdHQSThbzhaMvFIv
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1+(#a_01_25  & 1)*1+(#a_01_26  & 1)*1+(#a_01_27  & 1)*1+(#a_01_28  & 1)*1+(#a_01_29  & 1)*1+(#a_01_30  & 1)*1+(#a_01_31  & 1)*1) >=4
 
}