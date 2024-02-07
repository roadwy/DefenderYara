
rule Backdoor_Win32_Nuclear{
	meta:
		description = "Backdoor:Win32/Nuclear,SIGNATURE_TYPE_PEHSTR_EXT,50 00 46 00 48 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6c 6c 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00  dllfile\shell\open\command
		$a_01_1 = {25 77 5c 4e 52 } //02 00  %w\NR
		$a_01_2 = {25 61 6c 6c 5c } //01 00  %all\
		$a_01_3 = {50 72 6f 67 72 61 6d 46 69 6c 65 73 44 69 72 } //0a 00  ProgramFilesDir
		$a_02_4 = {55 8b ec 83 c4 f8 53 56 33 db 89 5d f8 89 4d fc 8b da 8b f0 8b 45 fc e8 90 02 04 33 c0 55 68 90 02 04 64 ff 30 64 89 20 8d 55 f8 8b 45 fc e8 90 02 04 8b 55 f8 8d 45 fc e8 90 02 04 8b 45 fc e8 90 02 04 50 56 e8 90 02 04 89 03 83 3b 00 0f 95 c0 8b d8 33 c0 5a 59 59 64 89 10 68 90 02 04 8d 45 f8 ba 02 00 00 00 e8 90 02 04 c3 90 00 } //05 00 
		$a_02_5 = {55 8b ec 81 c4 40 ff ff ff 53 56 57 8b da 89 45 fc 8b 45 fc e8 90 01 04 33 c0 55 68 90 01 04 64 ff 30 64 89 20 c7 85 40 ff ff ff 94 00 00 00 8d 85 40 ff ff ff 50 a1 90 01 02 fd 13 8b 00 ff d0 83 bd 50 ff ff ff 02 0f 85 87 00 00 00 8d 45 f8 50 6a 28 a1 90 01 02 fd 13 8b 00 ff d0 50 a1 90 01 02 fd 13 8b 00 ff d0 8d 45 e8 50 8b 45 fc e8 90 00 } //05 00 
		$a_02_6 = {50 6a 00 a1 90 01 02 fd 13 8b 00 ff d0 85 c0 74 45 c7 45 e4 01 00 00 00 84 db 74 09 c7 45 f0 02 00 00 00 eb 05 33 c0 89 45 f0 33 c0 89 45 f4 8d 75 e4 8d 7d d4 a5 a5 a5 a5 8d 45 f4 50 8d 45 d4 50 6a 10 8d 45 e4 50 6a 00 8b 45 f8 50 a1 90 01 02 fd 13 8b 00 ff d0 8b 45 f8 50 a1 90 01 02 fd 13 8b 00 ff d0 33 c0 5a 59 59 64 89 10 68 90 01 02 fd 13 8d 45 fc e8 90 01 04 c3 90 00 } //01 00 
		$a_01_7 = {4b 6f 66 63 4c 6f 7e 6f 66 6f 4e } //01 00  KofcLo~ofoN
		$a_01_8 = {66 66 6e 24 38 39 66 6f 64 78 6f 61 } //01 00  ffn$89fodxoa
		$a_01_9 = {6e 64 7d 73 6b 78 7e 55 66 66 6f 62 59 } //01 00  nd}skx~UffobY
		$a_01_10 = {77 73 6f 63 6b 33 32 2e 64 6c 6c 20 77 73 32 5f 33 32 2e 64 6c 6c 20 6d 73 77 73 6f 63 6b 2e 64 6c 6c } //01 00  wsock32.dll ws2_32.dll mswsock.dll
		$a_01_11 = {6f 67 63 5e 6f 66 63 4c 7e 6f 59 } //01 00  ogc^ofcL~oY
		$a_01_12 = {4b 73 78 65 7e 69 6f 78 63 4e 6f 7e 6b 6f 78 49 } //01 00  Ksxe~ioxcNo~koxI
		$a_01_13 = {6e 65 47 7e 6f 4d } //01 00  neG~oM
		$a_01_14 = {4b 73 6f 41 6f 7e 6f 66 6f 4e 6d 6f 58 } //01 00  KsoAo~ofoNmoX
		$a_01_15 = {6f 66 63 4c 6f 7e 63 78 5d } //01 00  ofcLo~cx]
		$a_01_16 = {78 6f 7e 66 63 4c 64 65 63 7e 7a 6f 69 72 4f 6e 6f 66 6e 64 6b 62 64 5f 7e 6f 59 } //01 00  xo~fcLdec~zoirOnofndkbd_~oY
		$a_01_17 = {79 6f 69 63 7c 78 6f 59 64 } //01 00  yoic|xoYd
		$a_01_18 = {4b 72 4f 73 6f 41 64 6f 7a 45 6d 6f 58 } //01 00  KrOsoAdozEmoX
		$a_01_19 = {4b 67 65 7e 4b 6e 64 63 4c 66 6b 68 65 66 4d } //01 00  Kge~KndcLfkhefM
		$a_01_20 = {65 79 6f 58 61 69 65 46 } //01 00  eyoXaieF
		$a_01_21 = {68 63 78 7e 7e 4b 6f 66 63 4c 7e 6f 59 } //01 00  hcx~~KofcL~oY
		$a_01_22 = {4b 6f 67 6b 44 6f 66 63 4c 6f 66 } //01 00  KogkDofcLof
		$a_01_23 = {79 6f 6d 6f 66 63 7c 63 78 5a 64 6f 61 65 5e 7e 79 } //01 00  yomofc|cxZdoae^~y
		$a_01_24 = {4b 6f 66 6e 64 6b 42 6f 66 } //01 00  KofndkBof
		$a_01_25 = {79 79 6f 69 65 78 5a 7e 64 6f 78 78 } //01 00  yyoiexZ~doxx
		$a_01_26 = {73 78 65 67 6f 47 79 79 6f 69 65 78 5a 6f 7e 63 78 5d } //01 00  sxegoGyyoiexZo~cx]
		$a_01_27 = {69 6f 72 4f 66 66 6f 62 59 } //01 00  iorOffobY
		$a_01_28 = {4b 6f 66 63 4c 73 7a 65 49 } //01 00  KofcLszeI
		$a_01_29 = {7e 78 6b 7e 59 7e 6f 4d } //01 00  ~xk~Y~oM
		$a_01_30 = {65 79 6f 58 6e 6b 65 46 } //01 00  eyoXnkeF
		$a_01_31 = {73 6f 41 6f 79 65 66 49 6d 6f 58 } //01 00  soAoyefImoX
		$a_01_32 = {4b 73 78 65 7e 69 6f 78 63 4e 79 7d 65 6e 64 63 5d 7e 6f 4d } //01 00  Ksxe~ioxcNy}endc]~oM
		$a_01_33 = {4b 72 4f 64 65 63 79 78 6f 5c 7e 6f 4d } //01 00  KrOdecyxo\~oM
		$a_01_34 = {4b 72 4f 73 6f 41 6f 7e 6b 6f 78 49 6d 6f 58 } //01 00  KrOsoAo~koxImoX
		$a_01_35 = {68 63 78 7e 7e 4b 6f 66 63 4c 7e 6f 4d } //01 00  hcx~~KofcL~oM
		$a_01_36 = {58 56 64 65 63 79 78 6f 5c 7e 64 6f 78 78 } //01 00  XVdecyxo\~doxx
		$a_01_37 = {69 6f 72 4f 6e 64 63 4c } //01 00  iorOndcL
		$a_01_38 = {4b 79 79 6f 69 65 78 5a 6f 7e 6b 6f 78 49 } //01 00  KyyoiexZo~koxI
		$a_01_39 = {65 79 6f 58 6e 64 63 4c } //01 00  eyoXndcL
		$a_01_40 = {6f 66 63 4c 64 6f 7a 45 } //01 00  ofcLdozE
		$a_01_41 = {7e 6f 59 2a 6f 7c 63 7e 69 4b 56 7e 6c 65 79 65 78 69 63 47 56 4f 58 4b 5d 5e 4c 45 59 } //01 00  ~oY*o|c~iKV~leyexicGVOXK]^LEY
		$a_01_42 = {65 79 6f 58 6c 65 6f 70 63 59 } //01 00  eyoXleopcY
		$a_01_43 = {6f 67 63 5e 6f 66 63 4c 7e 6f 4d } //01 00  ogc^ofcL~oM
		$a_01_44 = {73 78 6b 78 68 63 46 6f 6f 78 4c } //01 00  sxkxhcFooxL
		$a_01_45 = {6e 6b 6f 78 62 5e 6f 7e 65 67 6f 58 6f 7e 6b 6f 78 49 } //01 00  nkoxb^o~egoXo~koxI
		$a_01_46 = {64 6f 61 65 5e 79 79 6f 69 65 78 5a 64 6f 7a 45 } //01 00  doae^yyoiexZdozE
		$a_01_47 = {4b 6f 66 68 6b 7e } //01 00  Kofhk~
		$a_01_48 = {67 65 7e 4b 6f 7e 6f 66 6f 4e 66 6b 68 65 66 4d } //01 00  ge~Ko~ofoNfkhefM
		$a_01_49 = {66 6b 5c 73 78 6f } //01 00  fk\sxo
		$a_01_50 = {4b 72 65 48 6f 6d 6b 79 79 6f 47 } //01 00  KreHomkyyoG
		$a_01_51 = {79 79 6f 69 65 78 5a 64 6f 7a 45 } //01 00  yyoiexZdozE
		$a_01_52 = {49 56 79 7d 65 6e 64 63 5d 56 7e 6c 65 79 65 78 69 63 47 56 4f 58 4b 5d 5e 4c 45 59 } //01 00  IVy}endc]V~leyexicGVOXK]^LEY
		$a_01_53 = {4b 63 7a 67 69 78 7e 79 66 } //01 00  Kczgix~yf
		$a_01_54 = {72 4f 69 65 66 66 4b 66 6b } //01 00  rOieffKfk
		$a_01_55 = {66 6b 5c 7e 6f 59 6d 6f 58 } //01 00  fk\~oYmoX
		$a_01_56 = {4b 7d 65 6e 64 63 5d 6e 64 63 4c } //01 00  K}endc]ndcL
		$a_01_57 = {62 7e 6b 5a 68 } //01 00  b~kZh
		$a_01_58 = {6e 43 79 79 6f 69 65 78 5a 6e 6b 6f 78 62 5e 7d 65 6e 64 63 5d 7e 6f 4d } //01 00  nCyyoiexZnkoxb^}endc]~oM
		$a_01_59 = {66 6b 5c 6f 6d 6f 66 63 7c 63 78 5a 7a } //01 00  fk\omofc|cxZz
		$a_01_60 = {4b 6f 66 63 4c 6f 7e 6b 6f 78 49 } //01 00  KofcLo~koxI
		$a_01_61 = {6f 66 6e 64 6b 42 6f 79 65 66 49 } //01 00  ofndkBoyefI
		$a_01_62 = {4b 6f 67 6b 44 62 7e 6b 5a 6d 64 65 46 7e 6f 4d } //01 00  KogkDb~kZmdeF~oM
		$a_01_63 = {4b 65 6c 64 43 7a } //01 00  KeldCz
		$a_01_64 = {4b 73 7a 69 78 7e 79 66 } //01 00  Kszix~yf
		$a_01_65 = {4b 73 78 65 7e 69 6f 78 63 4e 67 6f 7e 79 73 59 7e 6f 4d } //01 00  Ksxe~ioxcNgo~ysY~oM
		$a_01_66 = {6f 79 65 66 49 6e 64 63 4c } //01 00  oyefIndcL
		$a_01_67 = {79 79 6f 69 65 78 5a 7e 63 72 4f } //01 00  yyoiexZ~crO
		$a_01_68 = {4b 7e 6b 69 78 7e 79 66 } //01 00  K~kix~yf
		$a_01_69 = {4b 6f 66 63 4c 7e 79 78 63 4c 6e 64 63 4c } //01 00  KofcL~yxcLndcL
		$a_01_70 = {4b 64 73 7a 69 78 7e 79 66 } //01 00  Kdszix~yf
		$a_01_71 = {65 79 6f 58 6f 6f 78 4c } //00 00  eyoXooxL
	condition:
		any of ($a_*)
 
}