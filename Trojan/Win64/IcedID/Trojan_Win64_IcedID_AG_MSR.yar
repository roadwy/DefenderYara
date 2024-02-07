
rule Trojan_Win64_IcedID_AG_MSR{
	meta:
		description = "Trojan:Win64/IcedID.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 89 4c 24 20 4c 89 44 24 18 66 3b c0 74 b8 e6 c4 90 ff d1 48 c1 ed 97 90 48 f7 f4 48 f7 f7 48 81 f9 d6 16 00 00 48 ff cb 48 81 d6 3d 0d 00 00 49 ff c4 48 85 dd e6 25 49 f7 d6 48 ff c3 48 f7 e6 4d 33 c0 49 f7 f8 41 5c e4 eb 49 ff c8 4d 23 c9 48 33 ff 48 81 f9 01 08 00 00 41 5a 49 f7 fa e6 9b ff d2 48 69 ff d1 26 00 00 49 8b f2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_AG_MSR_2{
	meta:
		description = "Trojan:Win64/IcedID.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {48 ff cf 4c 0f ac f6 5e 48 c1 e6 5e 49 c1 ee 15 4d 3b e3 49 c7 c6 be 15 00 00 48 f7 e2 49 f7 db 4d 69 ff 81 0e 00 00 48 33 d2 e4 fe 48 33 c9 48 f7 f1 48 ff c6 48 0f ac fd 6e 48 c1 e5 6e 4d 8b c6 48 ff cd 48 69 c0 ee 1b 00 00 48 f7 c3 5a 17 00 00 48 f7 d3 41 5f 48 33 ed 49 81 e2 40 1b 00 00 48 ff cd 49 81 d5 c7 04 00 00 49 ff cc 49 f7 d6 49 83 fd 2e 49 81 dc e9 07 00 00 4d 33 c0 4c 3b d5 49 81 e3 45 16 00 00 c8 b3 00 00 90 e4 f9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_AG_MSR_3{
	meta:
		description = "Trojan:Win64/IcedID.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {4a 64 68 71 6d 4d 4a } //01 00  JdhqmMJ
		$a_01_1 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00  PluginInit
		$a_01_2 = {58 42 4a 58 47 76 6b 6c 58 57 } //01 00  XBJXGvklXW
		$a_01_3 = {6f 6f 66 6f 75 55 57 79 66 } //01 00  oofouUWyf
		$a_01_4 = {70 5a 51 4e 6a 50 55 68 59 45 } //01 00  pZQNjPUhYE
		$a_01_5 = {77 68 5a 63 55 4f 67 68 52 57 4a } //01 00  whZcUOghRWJ
		$a_01_6 = {47 68 6f 73 74 53 63 72 69 70 74 2c } //02 00  GhostScript,
		$a_01_7 = {30 37 30 31 30 37 31 36 32 61 31 34 61 63 39 37 35 61 61 30 39 65 31 37 36 37 62 64 63 64 63 63 31 34 33 64 35 66 63 64 38 62 32 38 38 37 62 66 39 63 61 33 31 37 32 30 62 65 } //00 00  070107162a14ac975aa09e1767bdcdcc143d5fcd8b2887bf9ca31720be
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_AG_MSR_4{
	meta:
		description = "Trojan:Win64/IcedID.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 48 55 49 55 47 4c 4b } //01 00  AHUIUGLK
		$a_01_1 = {45 56 53 76 74 6f 44 57 6f 56 56 } //01 00  EVSvtoDWoVV
		$a_01_2 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00  PluginInit
		$a_01_3 = {59 44 6c 6c 79 53 59 } //01 00  YDllySY
		$a_01_4 = {72 6f 52 44 4c 58 76 } //01 00  roRDLXv
		$a_01_5 = {74 55 66 58 51 74 57 6c } //01 00  tUfXQtWl
		$a_01_6 = {4d 62 6f 71 6d 49 68 6e 59 33 43 47 78 34 4e 69 76 58 77 33 48 4e 58 4e 53 46 45 65 66 31 74 58 4c } //02 00  MboqmIhnY3CGx4NivXw3HNXNSFEef1tXL
		$a_01_7 = {65 61 38 39 32 31 35 30 61 33 61 33 65 64 36 37 37 65 31 62 31 37 61 64 64 36 33 35 30 30 31 32 62 39 33 38 65 61 35 63 37 34 66 66 37 37 63 64 31 30 37 30 33 66 62 61 62 30 32 34 63 65 36 35 31 30 34 64 37 37 63 34 33 } //00 00  ea892150a3a3ed677e1b17add6350012b938ea5c74ff77cd10703fbab024ce65104d77c43
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_AG_MSR_5{
	meta:
		description = "Trojan:Win64/IcedID.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 74 45 67 6c 56 75 53 68 4e 62 } //01 00  BtEglVuShNb
		$a_01_1 = {45 4f 41 54 54 42 63 57 77 73 } //01 00  EOATTBcWws
		$a_01_2 = {46 66 78 70 6d 72 5a 48 66 68 } //01 00  FfxpmrZHfh
		$a_01_3 = {47 61 62 73 64 6a 61 73 6a 6b 61 64 6e 68 62 6a 61 73 6b 6a } //01 00  Gabsdjasjkadnhbjaskj
		$a_01_4 = {4b 67 77 57 4b 43 } //01 00  KgwWKC
		$a_01_5 = {58 6d 68 59 48 6a 63 43 45 48 } //01 00  XmhYHjcCEH
		$a_01_6 = {52 39 4b 53 74 4c 54 59 49 32 58 30 79 6c 30 66 67 61 72 30 76 5a 37 44 54 4d 78 6b 75 36 4b 6c 69 } //02 00  R9KStLTYI2X0yl0fgar0vZ7DTMxku6Kli
		$a_01_7 = {65 33 63 30 63 31 38 61 38 66 37 64 35 31 34 62 66 64 65 37 65 30 31 61 30 30 37 37 39 35 65 62 34 61 61 33 37 36 39 30 36 31 64 65 32 61 61 62 30 66 64 63 32 38 34 35 34 37 33 63 } //00 00  e3c0c18a8f7d514bfde7e01a007795eb4aa3769061de2aab0fdc2845473c
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_AG_MSR_6{
	meta:
		description = "Trojan:Win64/IcedID.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6b 64 58 74 62 48 57 48 4c 42 } //01 00  IkdXtbHWHLB
		$a_01_1 = {4a 57 4a 6f 5a 54 6c 35 63 79 } //01 00  JWJoZTl5cy
		$a_01_2 = {52 44 78 77 4b 41 56 50 } //01 00  RDxwKAVP
		$a_01_3 = {64 34 73 43 36 7a 4f 43 65 30 } //01 00  d4sC6zOCe0
		$a_01_4 = {69 56 49 55 58 4a 36 } //01 00  iVIUXJ6
		$a_01_5 = {73 71 79 61 33 4e 68 72 } //01 00  sqya3Nhr
		$a_01_6 = {76 39 53 49 55 5a 30 6d 44 } //01 00  v9SIUZ0mD
		$a_01_7 = {77 61 75 68 64 68 62 73 6a 61 6b 64 6a 75 68 61 73 } //01 00  wauhdhbsjakdjuhas
		$a_01_8 = {7a 4a 36 49 50 51 50 4c 77 46 51 } //02 00  zJ6IPQPLwFQ
		$a_01_9 = {38 66 64 66 34 66 37 64 35 34 32 39 33 36 63 66 32 35 34 64 31 39 61 61 31 35 65 64 38 37 38 34 31 39 39 34 31 33 66 38 66 32 66 66 62 32 33 39 65 65 61 64 63 65 66 62 66 61 32 62 38 65 35 34 32 37 } //00 00  8fdf4f7d542936cf254d19aa15ed8784199413f8f2ffb239eeadcefbfa2b8e5427
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_AG_MSR_7{
	meta:
		description = "Trojan:Win64/IcedID.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 45 6f 63 67 47 78 66 5a 4d 4c 44 66 52 6c 55 4a } //01 00  CEocgGxfZMLDfRlUJ
		$a_01_1 = {45 4c 51 61 48 6c 50 55 4a 46 62 4c 6b 4a 46 } //01 00  ELQaHlPUJFbLkJF
		$a_01_2 = {4e 68 74 4e 7a 67 71 62 64 58 54 6c 6d 6f 7a 6f 4b } //02 00  NhtNzgqbdXTlmozoK
		$a_01_3 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00  PluginInit
		$a_01_4 = {6e 5a 44 63 6c 6d 55 78 79 53 62 46 44 5a 6b 70 64 6a 41 56 } //01 00  nZDclmUxySbFDZkpdjAV
		$a_01_5 = {74 65 55 68 54 45 71 5a 6e 77 6c 4c 53 4d 56 52 54 77 } //02 00  teUhTEqZnwlLSMVRTw
		$a_01_6 = {32 61 30 39 65 36 66 37 64 63 39 35 39 64 33 62 64 34 33 36 34 34 65 61 61 39 36 34 35 37 63 62 38 33 39 31 32 30 32 35 65 35 33 64 34 38 65 61 64 63 66 35 62 38 33 39 61 65 61 36 63 30 36 35 61 64 66 63 38 30 36 66 66 36 33 64 } //00 00  2a09e6f7dc959d3bd43644eaa96457cb83912025e53d48eadcf5b839aea6c065adfc806ff63d
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_AG_MSR_8{
	meta:
		description = "Trojan:Win64/IcedID.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 44 39 41 71 4b 43 33 49 6e } //01 00  CD9AqKC3In
		$a_01_1 = {43 50 4e 70 65 49 } //01 00  CPNpeI
		$a_01_2 = {48 50 44 4e 48 36 68 6b 30 44 4f } //01 00  HPDNH6hk0DO
		$a_01_3 = {4c 6b 6b 38 5a 56 62 79 } //01 00  Lkk8ZVby
		$a_01_4 = {4e 39 79 4b 79 74 56 55 59 43 44 } //01 00  N9yKytVUYCD
		$a_01_5 = {4f 7a 75 50 6a 49 38 71 43 75 } //01 00  OzuPjI8qCu
		$a_01_6 = {52 6f 34 6e 79 6d } //01 00  Ro4nym
		$a_01_7 = {56 79 35 36 31 77 45 } //01 00  Vy561wE
		$a_01_8 = {58 44 30 67 62 68 } //01 00  XD0gbh
		$a_01_9 = {62 6a 6c 35 4c 4f } //01 00  bjl5LO
		$a_01_10 = {74 73 74 37 42 69 71 } //01 00  tst7Biq
		$a_01_11 = {77 61 75 68 64 68 62 73 6a 61 6b 64 6a 75 68 61 73 } //02 00  wauhdhbsjakdjuhas
		$a_01_12 = {38 32 34 32 61 39 33 65 36 63 36 64 39 32 64 37 38 65 37 36 64 63 31 62 66 33 37 39 32 66 39 38 36 66 34 65 39 61 34 32 33 32 31 65 37 62 39 38 31 39 32 35 35 31 62 35 66 66 63 33 34 38 34 66 36 32 39 39 65 34 33 34 32 64 34 36 30 31 33 37 } //00 00  8242a93e6c6d92d78e76dc1bf3792f986f4e9a42321e7b98192551b5ffc3484f6299e4342d460137
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_AG_MSR_9{
	meta:
		description = "Trojan:Win64/IcedID.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 11 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 6b 70 76 56 53 66 64 6b 54 } //01 00  OkpvVSfdkT
		$a_01_1 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00  PluginInit
		$a_01_2 = {52 42 44 4e 63 64 6f 4c } //01 00  RBDNcdoL
		$a_01_3 = {52 68 59 53 4d 66 63 6c 49 61 79 } //01 00  RhYSMfclIay
		$a_01_4 = {54 41 4c 42 65 4f } //01 00  TALBeO
		$a_01_5 = {58 70 4e 6c 69 69 4e } //01 00  XpNliiN
		$a_01_6 = {5a 7a 66 6c 71 4e 68 } //01 00  ZzflqNh
		$a_01_7 = {63 6d 51 48 76 61 } //01 00  cmQHva
		$a_01_8 = {69 57 49 50 76 41 4d 6d } //01 00  iWIPvAMm
		$a_01_9 = {6a 6d 4d 54 7a 68 68 5a 65 49 68 } //01 00  jmMTzhhZeIh
		$a_01_10 = {6d 6b 55 70 75 62 63 6f 65 67 4e } //01 00  mkUpubcoegN
		$a_01_11 = {6e 51 6a 5a 46 45 49 56 75 67 50 } //01 00  nQjZFEIVugP
		$a_01_12 = {6e 58 6b 64 79 51 62 67 } //01 00  nXkdyQbg
		$a_01_13 = {6f 4f 43 51 4c 74 4a 6f 4d 49 4d } //01 00  oOCQLtJoMIM
		$a_01_14 = {74 58 42 4f 63 54 7a 51 } //01 00  tXBOcTzQ
		$a_01_15 = {7a 4d 56 50 70 56 43 61 7a 4c 6f } //02 00  zMVPpVCazLo
		$a_01_16 = {61 31 34 35 34 63 64 38 30 30 38 38 32 62 37 30 32 37 34 31 64 32 32 64 30 64 37 31 30 30 39 39 35 37 32 34 33 37 34 65 61 63 34 66 63 61 65 36 33 65 34 36 62 30 36 65 38 37 31 63 35 32 35 33 62 65 32 37 65 34 39 30 63 65 32 62 38 64 } //00 00  a1454cd800882b702741d22d0d7100995724374eac4fcae63e46b06e871c5253be27e490ce2b8d
	condition:
		any of ($a_*)
 
}