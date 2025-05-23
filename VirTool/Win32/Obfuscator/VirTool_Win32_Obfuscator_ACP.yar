
rule VirTool_Win32_Obfuscator_ACP{
	meta:
		description = "VirTool:Win32/Obfuscator.ACP,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 6a 00 00 "
		
	strings :
		$a_03_0 = {0f af fe 03 7d ?? 8d b2 ?? ?? ?? ?? 33 f0 89 7d ?? 81 fe ?? ?? ?? ?? 0f 85 0c 00 00 00 8b 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 75 ?? 8b 7d ?? 33 f0 33 f8 03 fa } //1
		$a_01_1 = {63 62 7a 78 6e 61 73 6b 6a 64 68 62 63 7a 78 6d 6e 62 00 } //1
		$a_03_2 = {8b 4d 08 8b 55 ?? 83 c0 04 8b 30 89 34 8a 8b 4d ?? 8b 55 08 33 cf 8d 8c 11 ?? ?? ?? ?? 89 4d 08 8b 4d 08 8b 55 14 3b ca 0f 85 d2 ff ff ff } //1
		$a_03_3 = {43 3a 5c 54 65 73 74 5c 46 69 6c 65 2e 74 78 74 00 00 00 00 ?? ?? ?? ?? 2a 2e 74 78 74 00 } //1
		$a_03_4 = {2b df 8b 7c 24 ?? 0f af df 03 5c 24 ?? 81 c6 ?? ?? ?? ?? 81 f6 ?? ?? ?? ?? 89 5c 24 ?? 81 fe ?? ?? ?? ?? 0f 85 90 09 09 00 8b 7c 24 ?? bb } //1
		$a_03_5 = {33 f9 33 d8 03 fe 13 da 89 7c 24 ?? 89 5c 24 ?? 8b 54 24 ?? 8b 74 24 ?? 8b 74 24 ?? 0f af d6 03 54 24 } //1
		$a_03_6 = {33 d1 33 f0 03 d3 89 54 24 ?? 13 f7 89 74 24 ?? 8b 54 24 ?? 8b 74 24 ?? 8b 74 24 ?? 0f af d6 03 54 24 } //1
		$a_03_7 = {01 30 8b 44 24 ?? 8b 74 24 ?? 33 c2 33 f1 05 ?? ?? ?? ?? 81 d6 ?? ?? ?? ?? 0b c6 0f 85 } //1
		$a_03_8 = {01 1a 8b 54 24 ?? 8b 5c 24 ?? 33 d1 33 d8 03 d7 13 de 0b d3 0f 85 } //1
		$a_01_9 = {5c 53 69 67 6e 75 6d 5c 4a 65 69 68 61 72 64 2e 65 78 65 00 } //1
		$a_01_10 = {52 75 62 79 57 6f 72 6b 2e 65 78 65 00 41 63 74 69 6f 6e 50 6c 61 59 00 } //1 畒祢潗歲攮數䄀瑣潩偮慬Y
		$a_03_11 = {01 32 8b 54 24 ?? 8b 74 24 ?? 33 d0 33 f7 03 d1 13 f7 0b d6 0f 85 } //1
		$a_03_12 = {01 1f 8b 7c 24 ?? 8b 5c 24 ?? 33 f8 33 d9 03 fe 13 da 0b fb 0f 85 } //1
		$a_01_13 = {30 39 73 61 38 64 69 70 61 73 6c 64 61 73 30 39 64 61 30 73 30 39 69 64 70 61 73 00 } //1 㤰慳搸灩獡摬獡㤰慤猰㤰摩慰s
		$a_03_14 = {01 32 8b 54 24 ?? 8b 74 24 ?? 8b 5c 24 ?? 33 d0 33 f7 03 d1 13 f7 89 5c 24 ?? 3b da 0f 85 } //1
		$a_03_15 = {89 0a 8b 4c 24 ?? 8b 54 24 ?? 33 c8 33 (d6|d7) 03 (|) ce cf 13 (d6|d7) 0b ca 0f 85 } //1
		$a_03_16 = {33 c6 33 cf 03 c2 8b 54 24 ?? 13 cf 3b d0 0f 85 ?? ?? ?? ?? 3b f9 0f 84 } //1
		$a_03_17 = {01 08 8b 44 24 ?? 8b 0d ?? ?? ?? ?? 8b 09 89 08 8b 44 24 ?? 8b 00 } //1
		$a_01_18 = {77 65 39 32 33 38 34 37 32 39 38 37 72 65 33 32 39 34 37 38 32 39 33 38 75 74 30 32 33 34 39 38 00 } //1
		$a_03_19 = {89 01 8b 44 24 ?? 8b 0d ?? ?? ?? ?? 8b 09 [0-01] 89 08 8b 44 24 ?? 8b 00 } //1
		$a_01_20 = {37 32 68 64 61 73 6b 75 6a 68 64 62 61 6e 73 64 62 6d 61 6e 62 73 64 6b 61 6a 73 68 00 } //1
		$a_01_21 = {2c 6d 78 63 6e 7a 78 6c 6b 6a 68 63 6b 6a 73 64 00 } //1
		$a_03_22 = {01 08 8b 44 24 ?? 8b 0d ?? ?? ?? ?? 8b 09 5f 89 08 8b 44 24 ?? 8b 00 } //1
		$a_01_23 = {35 38 37 36 35 38 37 36 30 39 37 2d 30 39 37 2d 30 36 30 38 36 00 } //1 㠵㘷㠵㘷㤰ⴷ㤰ⴷ㘰㠰6
		$a_03_24 = {33 d1 03 d0 89 54 24 ?? 8b 54 24 ?? 85 d2 0f 84 ?? ?? 00 00 a1 90 09 08 00 8b 54 24 ?? 8b 74 24 } //1
		$a_03_25 = {33 d1 03 d0 89 54 24 ?? 83 44 24 ?? ?? 83 54 24 ?? ?? 8b 54 24 ?? 85 d2 0f 84 ?? ?? 00 00 a1 90 09 08 00 8b 54 24 ?? 8b 74 24 } //1
		$a_01_26 = {53 63 69 65 6e 63 65 4d 6f 6f 45 00 } //1 捓敩据䵥潯E
		$a_03_27 = {33 d0 33 d9 81 c2 ?? ?? ?? ?? 13 df 0b d3 0f 85 ?? ?? ff ff 90 09 08 00 8b 54 24 ?? 8b 5c 24 } //1
		$a_01_28 = {30 00 34 00 39 00 31 00 32 00 2d 00 32 00 31 00 30 00 34 00 38 00 31 00 32 00 30 00 37 00 35 00 31 00 32 00 39 00 2d 00 32 00 00 00 } //1
		$a_03_29 = {8b 09 5f 89 08 8b 44 24 ?? 8b 00 5e 5b 8b e5 5d c2 90 09 0a 00 8b 44 24 ?? 8b 0d } //1
		$a_03_30 = {43 79 62 6f 72 67 41 72 65 61 2e (65 78 65|64 6c 6c) 00 4c 6f 77 53 6d 6f 6f 74 68 53 65 6e 73 45 } //1
		$a_03_31 = {33 d9 33 d0 be ?? ?? ?? ?? 03 d6 bf ?? ?? ?? ?? 13 df 89 5c 24 ?? 8b 5c 24 ?? 3b d3 0f 85 90 09 08 00 8b 54 24 ?? 8b 5c 24 } //1
		$a_01_32 = {4c 61 6e 64 69 6e 67 46 61 72 6d 2e 65 78 65 00 45 61 72 74 68 43 6f 6d 6d 6f 45 } //1
		$a_03_33 = {33 d8 33 f9 be ?? ?? ?? ?? 03 fe ba ?? ?? ?? ?? 13 da 89 5c 24 ?? 8b 5c 24 ?? 3b fb 0f 85 90 09 08 00 8b 7c 24 ?? 8b 5c 24 } //1
		$a_03_34 = {33 d6 33 c1 03 c3 13 d7 0b c2 0f 85 ?? ?? ff ff 90 09 08 00 8b 44 24 ?? 8b 54 24 } //1
		$a_03_35 = {33 d7 33 c1 03 c6 13 d3 0b c2 0f 85 ?? ?? ff ff 90 09 08 00 8b 44 24 ?? 8b 54 24 } //1
		$a_03_36 = {43 6f 6e 74 72 46 69 72 65 2e (65 78 65|64 6c 6c) 00 48 69 67 68 57 61 79 53 65 45 } //1
		$a_03_37 = {33 c6 33 cf 05 ?? ?? ?? ?? 81 d1 ?? ?? ?? ?? 0b c1 0f 85 90 09 06 00 8b 45 ?? 8b 4d } //1
		$a_01_38 = {8b 45 b0 8b 4d d8 0f b7 04 48 8b 4d dc 8b 04 81 89 45 dc } //1
		$a_03_39 = {01 32 8b 54 24 ?? 8b 74 24 ?? 33 90 04 01 02 d0 d1 03 90 04 01 02 d1 d0 89 15 ?? ?? ?? ?? 8b 44 24 ?? 8b 00 } //1
		$a_01_40 = {33 00 30 00 39 00 38 00 34 00 32 00 33 00 3d 00 32 00 33 00 34 00 39 00 32 00 33 00 30 00 3d 00 32 00 33 00 34 00 } //1 3098423=2349230=234
		$a_03_41 = {33 f8 33 f1 03 fa 81 d6 ?? ?? ?? ?? 33 db 3b de 0f 82 90 09 0c 00 8b 7c 24 ?? 89 74 24 ?? 8b 74 24 } //1
		$a_01_42 = {4e 61 74 75 72 61 6c 4c 61 62 2e 65 78 65 00 45 78 6f 50 6f 72 74 61 6c 49 45 } //1 慎畴慲䱬扡攮數䔀潸潐瑲污䕉
		$a_03_43 = {01 31 8b 4c 24 ?? 8b 74 ?? 34 33 c8 03 ca 89 0d ?? ?? ?? ?? 8b 44 24 ?? 8b 00 } //1
		$a_03_44 = {01 3e 8b 7c 24 ?? 8b 74 24 ?? 33 f8 33 f1 03 fa 81 d6 ?? ?? ?? ?? 33 db 3b de 0f 82 } //1
		$a_03_45 = {01 11 8b 4c 24 ?? 8b 54 24 ?? 33 c8 (03 90 04 01 02 ce cf|81 e9 ?? ?? ??) ?? 89 0d ?? ?? ?? ?? 8b 44 24 ?? 8b 00 } //1
		$a_03_46 = {33 f8 33 d1 03 fe 81 d2 ?? ?? ?? ?? 33 db 3b da 0f 82 90 09 04 00 8b 54 24 } //1
		$a_01_47 = {5c 32 33 35 39 38 32 33 37 39 35 38 37 32 38 33 00 } //1
		$a_01_48 = {5c 00 63 00 68 00 69 00 6c 00 64 00 72 00 65 00 6e 00 5b 00 30 00 32 00 39 00 33 00 5d 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_03_49 = {33 c1 89 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 69 c0 ?? ?? ?? ?? 03 45 } //1
		$a_03_50 = {01 10 8b 44 24 ?? 8b 54 24 ?? 33 c1 (05 ?? ?? ??|?? 03 ?? a3) ?? ?? ?? ?? 8b 44 24 ?? 8b 00 } //1
		$a_01_51 = {00 74 6f 72 65 64 53 69 72 65 57 75 67 65 72 74 2e 65 78 65 00 46 6f 72 54 69 72 65 45 78 70 6f 73 43 00 } //1
		$a_03_52 = {01 30 8b 44 24 ?? 8b 74 24 ?? 33 c2 03 c1 a3 ?? ?? ?? ?? 8b 44 24 ?? 8b 00 } //1
		$a_03_53 = {01 10 8b 44 24 ?? 8b 54 24 ?? 05 ?? ?? ?? ?? 81 d2 ?? ?? ?? ?? 33 c1 89 44 24 ?? 81 f2 ?? ?? ?? ?? 89 54 24 ?? 8b 44 24 ?? 8b 54 24 ?? 33 c1 03 c6 } //1
		$a_03_54 = {33 c9 03 c2 13 cb 89 45 ?? 89 4d ?? 8b 8d ?? ?? ?? ?? 8b 45 ?? 39 4d ?? 0f 82 ?? ?? ?? ?? 0f 87 } //1
		$a_03_55 = {01 10 8b 54 24 ?? 8b 44 24 ?? 33 d1 35 ?? ?? ?? ?? 47 03 d6 15 ?? ?? ?? ?? 33 db 3b d8 0f 82 ?? ?? ?? ?? 0f 87 } //1
		$a_01_56 = {3f 6d 69 6c 69 74 61 72 79 4b 65 79 41 40 40 59 47 45 55 } //1 ?militaryKeyA@@YGEU
		$a_03_57 = {03 c1 89 44 24 ?? 8b 44 24 ?? 33 f2 33 c7 03 f1 13 c7 3b f8 0f 87 ?? ?? ?? ?? 0f 83 } //1
		$a_03_58 = {01 30 8b 44 24 ?? 8b 74 24 ?? 33 c2 03 c1 a3 ?? ?? ?? ?? e9 90 16 8b 44 24 ?? 8b 00 } //1
		$a_03_59 = {33 fa 33 f3 03 c1 03 f9 13 f3 3b de 0f 87 ?? 00 00 00 0f 83 ?? 00 00 00 } //1
		$a_01_60 = {03 cf 33 c0 33 ce 40 2b cb d3 e0 33 d2 89 45 } //1
		$a_03_61 = {66 03 0a 81 f1 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 66 89 4d ?? 66 8b 4d ?? 66 8b 55 ?? 66 3b ca 0f 85 } //1
		$a_03_62 = {33 c0 40 d3 e0 33 d2 89 45 ?? 8b c3 f7 75 ?? 29 55 ?? e9 } //1
		$a_03_63 = {01 08 8b 44 24 ?? 8b 4c 24 ?? (2d ?? ?? ??|?? 03) c6 33 c2 2d ?? ?? ?? ?? a3 ?? ?? ?? ?? e9 ?? 00 00 00 } //1
		$a_03_64 = {8b 45 ec 69 c0 ?? ?? ?? ?? 03 45 08 90 09 0e 00 c7 45 ec ?? ?? ?? ?? c7 45 08 } //1
		$a_03_65 = {8b 45 ec 69 c0 ?? ?? ?? ?? 01 45 08 90 09 0e 00 c7 45 ec ?? ?? ?? ?? c7 45 08 } //1
		$a_03_66 = {01 08 8b 44 24 ?? 8b 4c 24 ?? 03 c7 33 c6 03 c2 a3 ?? ?? ?? ?? e9 ?? 00 00 00 } //1
		$a_03_67 = {e9 0d 00 00 00 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 01 08 8b 44 24 ?? 8b 00 90 09 05 00 a3 } //1
		$a_03_68 = {8b 1b 31 1f 8b 7c 24 ?? 03 f9 8b 4c 24 ?? 33 fe 81 ef ?? ?? ?? ?? 89 39 } //1
		$a_03_69 = {8b 36 89 31 8b 4c 24 ?? 8b 74 24 ?? 81 c1 ?? ?? ?? ?? 13 f3 33 ca 33 f3 03 c8 8b 44 24 ?? 8b 00 } //1
		$a_03_70 = {0f b6 c0 01 45 f8 81 45 ?? ?? ?? ?? ?? 83 55 ?? ?? 8b 45 ?? 85 c0 0f 85 ?? ?? ff ff 8b 45 } //1
		$a_03_71 = {8b 80 dc 01 00 00 8b 08 a1 ?? ?? ?? ?? 09 08 90 09 07 00 01 08 a1 } //1
		$a_03_72 = {8b 00 99 83 d6 ff 3b c1 0f 85 ?? ?? 00 00 3b d6 0f 85 } //1
		$a_03_73 = {03 c6 33 c1 8d 84 18 ?? ?? ?? ?? 89 45 ?? a1 ?? ?? ?? ?? 8b 80 ?? ?? ?? ?? 83 20 00 } //1
		$a_03_74 = {8b 1b 31 18 e9 ?? ?? ff ff 83 20 00 e9 ?? ?? ff ff 90 09 06 00 8b 80 } //1
		$a_03_75 = {2b d8 03 5d ?? 89 5d ?? e9 ?? ?? ff ff 83 20 00 e9 ?? ?? ff ff } //1
		$a_03_76 = {2b d8 03 5d ?? 89 5d ?? 8b 45 ?? 8b 5d ?? 8b 1b 31 18 e9 ?? ?? ff ff 83 20 00 e9 } //1
		$a_03_77 = {8b 09 01 08 8b 45 ?? 8b 0d ?? ?? ?? ?? 8b 09 89 08 8b 45 ?? 8b 00 } //1
		$a_03_78 = {8b 09 31 08 8b 45 ?? 83 20 00 90 09 06 00 8b 45 ?? 8b 4d } //1
		$a_03_79 = {8b 3f 31 3a 8b 55 ?? 03 d0 8b 45 ?? 33 d1 2b d6 89 10 } //1
		$a_03_80 = {8b 1b 31 1f 8b 7d ?? 03 f9 8b 4d ?? 33 fa 81 ef ?? ?? ?? ?? 89 39 } //1
		$a_03_81 = {8b 1b 31 18 8b 45 ?? 8b 5d ?? 04 ?? 34 ?? 2c ?? 88 45 ?? 8a 45 ?? 84 c0 0f 85 } //1
		$a_03_82 = {8b 1b 31 18 e9 ?? ?? ff ff 83 20 00 e9 ?? ?? ff ff 90 09 06 00 8b 45 ?? 8b 5d } //1
		$a_03_83 = {8b 09 89 08 8b 45 ?? 8b 4d ?? 8b 09 01 08 8b 45 ?? 8b 00 } //1
		$a_03_84 = {8b 3f 31 38 8b 45 ?? 03 c1 8b 4d ec 33 c2 ?? c6 89 01 } //1
		$a_03_85 = {8b 12 31 10 8b 45 ?? 8b 55 ?? 8b 55 ?? 03 c6 33 c1 8d 84 10 ?? ?? ?? ?? 89 45 ?? e9 ?? ?? ff ff 83 20 00 e9 } //1
		$a_03_86 = {8b 09 31 08 8b 45 ?? 8b 4d ?? 03 c2 33 c6 2b c7 89 01 } //1
		$a_03_87 = {8b 09 31 08 8b 45 ?? 8b 4d ?? 8b 09 01 08 90 09 06 00 8b 45 ?? 8b 4d } //1
		$a_03_88 = {8b 09 89 08 33 c0 8b 4c 24 24 ?? 0c 01 88 4c 04 } //1
		$a_03_89 = {8b 09 31 08 8b 45 ?? 8b 0d ?? ?? ?? ?? 01 08 8b 45 ?? 8b 00 } //1
		$a_03_90 = {33 ce 33 d0 03 cf 13 d0 3b d9 0f 85 ?? ?? 00 00 39 55 ?? 0f 85 } //1
		$a_03_91 = {8b 3f 31 3e 8b 75 ?? 8b 7d ?? 03 f0 33 f1 2b f2 89 37 } //1
		$a_03_92 = {8b 12 89 10 8b 44 24 ?? 8b 00 99 05 ?? ?? ?? ?? 83 d2 ff 33 c1 } //1
		$a_03_93 = {33 c0 8b 4c 24 ?? 8a 54 04 ?? 88 14 01 40 83 f8 04 0f 82 } //1
		$a_03_94 = {03 c8 89 0e 8b 4d ?? 8b 75 ?? 03 f0 01 31 90 09 06 00 8b 4d ?? 8b 75 } //1
		$a_03_95 = {2b c8 89 0a 8b 55 ?? 8b 0a 8b 7d ?? 2b c8 03 f9 89 3a 8b 0d ?? ?? ?? ?? 46 3b f1 } //1
		$a_03_96 = {8b 12 89 10 8b 44 24 ?? 8b 00 99 05 ?? ?? ?? ?? 13 d7 33 c1 } //1
		$a_03_97 = {8b 12 31 11 8b 0d ?? ?? ?? ?? 33 f6 85 c9 0f 84 } //1
		$a_03_98 = {2b d0 03 fa 8b 55 ?? 89 3e 90 09 08 00 8b 75 ?? 8b 16 8b 7d } //1
		$a_03_99 = {8b 12 89 10 8b 44 24 ?? 8b 00 99 05 ?? ?? ?? ?? 13 d3 33 c1 } //1
		$a_03_100 = {8b 12 31 11 8b 4d ?? 8b 15 ?? ?? ?? ?? 2b c8 3b ca 0f 83 } //1
		$a_03_101 = {8b 12 31 11 8b 4d ?? 8b 55 ?? 8b 31 3b 32 0f 85 } //1
		$a_03_102 = {2b d1 3b da 0f 85 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 9a ?? ?? ?? ?? 33 d2 89 13 } //1
		$a_03_103 = {8b 09 31 08 8b 45 ?? 33 ?? 3b f8 0f 85 90 09 06 00 8b 45 ?? 8b 4d } //1
		$a_03_104 = {8b 09 31 08 8b 45 ?? 3b f8 0f 85 90 09 06 00 8b 45 ?? 8b 4d } //1
		$a_03_105 = {8b 44 24 08 8b 74 24 08 8b 36 31 30 8b 44 24 10 3b c8 90 09 07 00 33 06 a3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_03_11  & 1)*1+(#a_03_12  & 1)*1+(#a_01_13  & 1)*1+(#a_03_14  & 1)*1+(#a_03_15  & 1)*1+(#a_03_16  & 1)*1+(#a_03_17  & 1)*1+(#a_01_18  & 1)*1+(#a_03_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_03_22  & 1)*1+(#a_01_23  & 1)*1+(#a_03_24  & 1)*1+(#a_03_25  & 1)*1+(#a_01_26  & 1)*1+(#a_03_27  & 1)*1+(#a_01_28  & 1)*1+(#a_03_29  & 1)*1+(#a_03_30  & 1)*1+(#a_03_31  & 1)*1+(#a_01_32  & 1)*1+(#a_03_33  & 1)*1+(#a_03_34  & 1)*1+(#a_03_35  & 1)*1+(#a_03_36  & 1)*1+(#a_03_37  & 1)*1+(#a_01_38  & 1)*1+(#a_03_39  & 1)*1+(#a_01_40  & 1)*1+(#a_03_41  & 1)*1+(#a_01_42  & 1)*1+(#a_03_43  & 1)*1+(#a_03_44  & 1)*1+(#a_03_45  & 1)*1+(#a_03_46  & 1)*1+(#a_01_47  & 1)*1+(#a_01_48  & 1)*1+(#a_03_49  & 1)*1+(#a_03_50  & 1)*1+(#a_01_51  & 1)*1+(#a_03_52  & 1)*1+(#a_03_53  & 1)*1+(#a_03_54  & 1)*1+(#a_03_55  & 1)*1+(#a_01_56  & 1)*1+(#a_03_57  & 1)*1+(#a_03_58  & 1)*1+(#a_03_59  & 1)*1+(#a_01_60  & 1)*1+(#a_03_61  & 1)*1+(#a_03_62  & 1)*1+(#a_03_63  & 1)*1+(#a_03_64  & 1)*1+(#a_03_65  & 1)*1+(#a_03_66  & 1)*1+(#a_03_67  & 1)*1+(#a_03_68  & 1)*1+(#a_03_69  & 1)*1+(#a_03_70  & 1)*1+(#a_03_71  & 1)*1+(#a_03_72  & 1)*1+(#a_03_73  & 1)*1+(#a_03_74  & 1)*1+(#a_03_75  & 1)*1+(#a_03_76  & 1)*1+(#a_03_77  & 1)*1+(#a_03_78  & 1)*1+(#a_03_79  & 1)*1+(#a_03_80  & 1)*1+(#a_03_81  & 1)*1+(#a_03_82  & 1)*1+(#a_03_83  & 1)*1+(#a_03_84  & 1)*1+(#a_03_85  & 1)*1+(#a_03_86  & 1)*1+(#a_03_87  & 1)*1+(#a_03_88  & 1)*1+(#a_03_89  & 1)*1+(#a_03_90  & 1)*1+(#a_03_91  & 1)*1+(#a_03_92  & 1)*1+(#a_03_93  & 1)*1+(#a_03_94  & 1)*1+(#a_03_95  & 1)*1+(#a_03_96  & 1)*1+(#a_03_97  & 1)*1+(#a_03_98  & 1)*1+(#a_03_99  & 1)*1+(#a_03_100  & 1)*1+(#a_03_101  & 1)*1+(#a_03_102  & 1)*1+(#a_03_103  & 1)*1+(#a_03_104  & 1)*1+(#a_03_105  & 1)*1) >=1
 
}